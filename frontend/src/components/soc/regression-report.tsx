"use client";

import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { Tag } from "@/components/soc/badges";
import { tableCls } from "@/components/soc/common";
import type { RegressionReport, RegressionStatus } from "@/lib/types";
import { cn, nf } from "@/lib/utils";

const STATUS: Record<RegressionStatus, { label: string; tone: string; mark: string }> = {
  regressed: { label: "Regression", tone: "text-foreground", mark: "bg-critical" },
  missed: { label: "Still missed", tone: "text-foreground", mark: "bg-high" },
  noise_added: { label: "More noise", tone: "text-foreground", mark: "bg-medium" },
  fixed: { label: "Now detected", tone: "text-success", mark: "bg-success" },
  noise_reduced: { label: "Less noise", tone: "text-success", mark: "bg-success" },
  detected: { label: "Detected", tone: "text-muted", mark: "bg-border-strong" },
  unchanged: { label: "Unchanged", tone: "text-muted", mark: "bg-border-strong" },
};

const VERDICT_LABEL = { malicious: "attack", benign: "benign", false_positive: "false positive" } as const;

function Delta({ before, after, better }: { before: number; after: number; better: "up" | "down" }) {
  const changed = before !== after;
  const good = changed && (better === "up" ? after > before : after < before);
  return (
    <span className="inline-flex items-baseline gap-1.5 font-mono tabular-nums">
      <span className={cn(changed ? "text-subtle line-through decoration-1" : "text-foreground")}>{nf.format(before)}</span>
      {changed && (
        <>
          <ArrowRight className="size-3 self-center text-subtle" aria-label="becomes" />
          <span className={good ? "text-success" : "text-foreground"}>{nf.format(after)}</span>
        </>
      )}
    </span>
  );
}

/** Before/after view of a detection regression run: the gate verdict, attack coverage, noise, then per-scenario detail. */
export function RegressionReportView({ report }: { report: RegressionReport }) {
  const s = report.summary;
  const changes = Object.entries(report.changes);
  return (
    <div className="space-y-5">
      <div
        role="status"
        className={cn(
          "flex items-start gap-3 rounded-md border p-3",
          report.passed ? "border-success/30 bg-success/8" : "border-critical/30 bg-critical/8",
        )}
      >
        <span className={cn("mt-1 size-2 shrink-0 rounded-full", report.passed ? "bg-success" : "bg-critical")} aria-hidden />
        <div className="text-sm">
          <p className="font-semibold">
            {report.passed ? "Passed: no attack scenario lost its detection" : `Failed: ${s.regressions} attack scenario(s) would no longer be detected`}
          </p>
          <p className="mt-0.5 text-xs text-muted">
            {changes.length
              ? `Candidate: ${changes
                  .map(([id, c]) =>
                    [id, c.enabled === false ? "disabled" : c.enabled ? "enabled" : null, ...Object.entries(c.params ?? {}).map(([k, v]) => `${k}=${v}`)]
                      .filter(Boolean)
                      .join(" "),
                  )
                  .join("; ")}.`
              : "Health check of the rules currently in force."}{" "}
            Every scenario replayed with seeds {report.seeds.join(" and ")} on top of the baseline week.
          </p>
        </div>
      </div>

      <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-border bg-border sm:grid-cols-4">
        {[
          ["Attacks detected", <Delta key="d" before={s.detected_before} after={s.detected_after} better="up" />, `of ${s.attack_scenarios}`],
          ["Regressions", <span key="r" className="font-mono tabular-nums">{s.regressions}</span>, "attacks lost"],
          ["Fixes", <span key="f" className="font-mono tabular-nums">{s.fixes}</span>, "attacks gained"],
          ["Noise alerts", <Delta key="n" before={s.noise_before} after={s.noise_after} better="down" />, "baseline + benign"],
        ].map(([label, value, caption]) => (
          <div key={String(label)} className="bg-surface p-3">
            <dt className="eyebrow">{label}</dt>
            <dd className="mt-1.5 font-display text-xl font-semibold">{value}</dd>
            <dd className="text-2xs text-subtle">{caption}</dd>
          </div>
        ))}
      </dl>

      <section>
        <h3 className="mb-2 eyebrow">Scenarios</h3>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className={tableCls.table}>
            <thead className={tableCls.head}>
              <tr>
                <th className={tableCls.th}>Result</th>
                <th className={tableCls.th}>Scenario</th>
                <th className={tableCls.th}>Expected rules</th>
                <th className={cn(tableCls.th, "text-right")}>Alerts</th>
              </tr>
            </thead>
            <tbody>
              {report.scenarios.map((o) => {
                const st = STATUS[o.status];
                return (
                  <tr key={o.scenario_id} className={tableCls.row}>
                    <td className={cn(tableCls.td, "whitespace-nowrap")}>
                      <span className={cn("inline-flex items-center gap-2 text-xs font-medium", st.tone)}>
                        <span className={cn("h-3 w-[3px] rounded-full", st.mark)} aria-hidden />
                        {st.label}
                      </span>
                    </td>
                    <td className={cn(tableCls.td, "min-w-56")}>
                      <span className="block text-sm">{o.name}</span>
                      <span className="mt-0.5 flex flex-wrap gap-1">
                        <Tag>{VERDICT_LABEL[o.verdict]}</Tag>
                        {o.origin === "custom" && <Tag>custom</Tag>}
                      </span>
                    </td>
                    <td className={cn(tableCls.td, "font-mono text-xs")}>
                      {o.expected_rules.map((r) => {
                        const lost = o.missed_after.includes(r) && !o.missed_before.includes(r);
                        const gained = o.missed_before.includes(r) && !o.missed_after.includes(r);
                        const missing = o.missed_after.includes(r);
                        return (
                          <span
                            key={r}
                            className={cn("mr-2 whitespace-nowrap", missing ? "text-subtle line-through" : "text-muted", gained && "text-success no-underline")}
                            title={lost ? "Lost with the candidate" : gained ? "Gained with the candidate" : missing ? "Missed" : "Fires"}
                          >
                            {r}
                          </span>
                        );
                      })}
                    </td>
                    <td className={cn(tableCls.td, "text-right text-xs")}>
                      <Delta before={o.alerts_before} after={o.alerts_after} better={o.verdict === "malicious" ? "up" : "down"} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {report.baseline.length > 0 && (
        <section>
          <h3 className="mb-1 eyebrow">Noise on the baseline week</h3>
          <p className="mb-2 text-xs text-muted">Alerts on normal corporate activity, by rule. Lower is better as long as no attack is lost.</p>
          <ul className="flex flex-wrap gap-x-5 gap-y-1 text-xs">
            {report.baseline.map((b) => (
              <li key={b.rule_id} className="flex items-center gap-2">
                <Link href={`/rules?rule=${b.rule_id}`} className="font-mono text-primary hover:underline">
                  {b.rule_id}
                </Link>
                <Delta before={b.before} after={b.after} better="down" />
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
