"use client";

import { ArrowLeft, Download, FileJson, Printer } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { useSearchParams } from "next/navigation";
import useSWR from "swr";

import { SeverityBadge } from "@/components/soc/badges";
import { ErrorState, KeyValue } from "@/components/soc/common";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/primitives";
import type { IncidentReport } from "@/lib/types";
import { cn, downloadText, formatTs } from "@/lib/utils";
import { incidentHref } from "@/lib/routes";

function Section({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <section className="break-inside-avoid-page border-t border-border py-6 first:border-0 first:pt-0">
      <h2 className="mb-3 text-sm font-semibold">
        <span className="mr-2 font-mono text-subtle">{String(n).padStart(2, "0")}</span>
        {title}
      </h2>
      {children}
    </section>
  );
}

const th = "border-b border-border px-2 py-1.5 text-left font-mono text-2xs font-medium uppercase tracking-[0.06em] text-subtle";
const td = "border-b border-border/60 px-2 py-1.5 align-top text-sm";

function ReportPage() {
  const id = useSearchParams().get("id") ?? "";
  const { data: r, error, mutate } = useSWR<IncidentReport>(id ? `/incidents/${id}/report` : null);
  if (!id) return <ErrorState error={new Error("No record id in the URL.")} />;
  if (error) return <ErrorState error={error} retry={() => mutate()} />;
  if (!r) return <Skeleton className="h-[80vh] w-full" />;
  const inc = r.incident;

  return (
    <>
      <div className="no-print mb-4 flex flex-wrap items-center justify-between gap-2">
        <Link href={incidentHref(inc.id)} className="inline-flex items-center gap-1 text-xs text-muted hover:text-foreground">
          <ArrowLeft className="size-3.5" /> Back to {inc.id}
        </Link>
        <div className="flex gap-2">
          <Button asChild>
            <a href={`/api/incidents/${inc.id}/report.md`} download>
              <Download /> Markdown
            </a>
          </Button>
          <Button onClick={() => downloadText(`${inc.id}-report.json`, JSON.stringify(r, null, 2), "application/json")}>
            <FileJson /> JSON
          </Button>
          <Button variant="primary" onClick={() => window.print()}>
            <Printer /> Print / PDF
          </Button>
        </div>
      </div>

      <article className="print-surface mx-auto max-w-4xl rounded-lg border border-border bg-surface px-6 py-8 sm:px-10">
        <header className="mb-6">
          <div className="eyebrow !text-medium">{r.environment}</div>
          <h1 className="mt-2 font-display text-2xl font-semibold tracking-[-0.02em]">Incident report · {inc.id}</h1>
          <p className="mt-1 text-base text-muted">{inc.title}</p>
          <div className="mt-4 grid gap-x-8 gap-y-1 sm:grid-cols-2">
            <KeyValue
              items={[
                ["Severity", <SeverityBadge key="s" severity={inc.severity} />],
                ["Status", inc.status],
                ["Classification", r.classification_label],
                ["Analyst", r.analyst],
              ]}
            />
            <KeyValue
              items={[
                ["First seen", `${formatTs(inc.first_seen)} UTC`],
                ["Last seen", `${formatTs(inc.last_seen)} UTC`],
                ["Time to detect", r.metrics.time_to_detect ?? "-"],
                ["Generated", `${formatTs(r.generated_at, { seconds: false })} UTC`],
              ]}
            />
          </div>
        </header>

        <Section n={1} title="Executive summary">
          <p className="text-sm leading-relaxed">{r.executive_summary}</p>
          <p className="mt-2 text-xs text-muted">
            {r.metrics.event_count} events · {r.metrics.alert_count} alerts · acknowledged {r.metrics.time_to_acknowledge ?? "n/a"} · closed {r.metrics.time_to_close ?? "n/a"} after creation
          </p>
        </Section>

        <Section n={2} title="Scope">
          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <h3 className="mb-1 text-xs text-subtle">Hosts</h3>
              {r.scope.hosts.map((h) => (
                <p key={h.hostname} className="text-sm">
                  <strong className="font-medium">{h.hostname}</strong> <span className="text-muted">{h.role ?? ""}{h.criticality ? ` · ${h.criticality}` : ""}</span>
                </p>
              ))}
            </div>
            <div>
              <h3 className="mb-1 text-xs text-subtle">Accounts</h3>
              {r.scope.users.map((u) => (
                <p key={u.username} className="text-sm">
                  <strong className="font-medium">{u.username}</strong> <span className="text-muted">{u.display_name}{u.privileged ? " · privileged" : ""}</span>
                </p>
              ))}
              {!r.scope.users.length && <p className="text-sm text-muted">None</p>}
            </div>
            <div>
              <h3 className="mb-1 text-xs text-subtle">Source addresses</h3>
              {r.scope.ips.map((i) => (
                <p key={i.ip} className="text-sm">
                  <strong className="font-mono text-xs font-medium">{i.ip}</strong> <span className="text-muted">{i.internal ? "internal" : `${i.reputation ?? "external"} · ${i.organization ?? ""}`}</span>
                </p>
              ))}
              {!r.scope.ips.length && <p className="text-sm text-muted">None</p>}
            </div>
          </div>
        </Section>

        <Section n={3} title="Detections">
          <div className="overflow-x-auto"><table className="w-full min-w-[520px] border-collapse">
            <thead>
              <tr>
                <th className={th}>Time</th>
                <th className={th}>Rule</th>
                <th className={th}>Severity</th>
                <th className={th}>Reason</th>
              </tr>
            </thead>
            <tbody>
              {r.detections.map((a) => (
                <tr key={a.id}>
                  <td className={cn(td, "whitespace-nowrap font-mono text-xs")}>{formatTs(a.timestamp, { date: false })}</td>
                  <td className={td}>
                    <span className="font-mono text-xs text-muted">{a.rule_id}</span> {a.rule_name}
                  </td>
                  <td className={td}>{a.severity}</td>
                  <td className={cn(td, "text-muted")}>{a.reason}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        </Section>

        <Section n={4} title="MITRE ATT&CK mapping">
          <ul className="space-y-1 text-sm">
            {inc.mitre.map((m) => (
              <li key={m.technique_id}>
                <span className="font-mono text-xs">{m.technique_id}</span> {m.technique} <span className="text-muted">- {m.tactic}</span>
              </li>
            ))}
          </ul>
        </Section>

        <Section n={5} title="Timeline">
          <ol className="space-y-0.5 text-xs">
            {r.timeline.slice(0, 150).map((t, i) => (
              <li key={i} className={cn("flex flex-wrap gap-x-3 sm:flex-nowrap", t.kind === "alert" && "my-1 rounded-sm bg-primary/8 px-1.5 py-1 font-medium")}>
                <span className="w-36 shrink-0 font-mono text-muted">{formatTs(t.timestamp)}</span>
                <span className="w-20 shrink-0 text-subtle">{t.kind === "alert" ? "ALERT" : t.event_id}</span>
                <span className="min-w-0 [overflow-wrap:anywhere]">{t.title}</span>
              </li>
            ))}
          </ol>
          {r.timeline.length > 150 && <p className="mt-2 text-xs text-subtle">{r.timeline.length - 150} more entries in the JSON/Markdown export.</p>}
        </Section>

        <Section n={6} title="Indicators of compromise">
          {r.iocs.length ? (
            <div className="overflow-x-auto"><table className="w-full min-w-[520px] border-collapse">
              <thead>
                <tr>
                  <th className={th}>Type</th>
                  <th className={th}>Value</th>
                  <th className={th}>Context</th>
                </tr>
              </thead>
              <tbody>
                {r.iocs.map((i) => (
                  <tr key={i.type + i.value}>
                    <td className={td}>{i.type}</td>
                    <td className={cn(td, "break-all font-mono text-xs")}>{i.value}</td>
                    <td className={cn(td, "text-muted")}>{i.context}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          ) : (
            <p className="text-sm text-muted">No external indicators identified.</p>
          )}
        </Section>

        <Section n={7} title="Evidence (raw logs)">
          <div className="space-y-1.5">
            {r.evidence.slice(0, 12).map((e) => (
              <div key={e.event_ref} className="rounded-sm border border-border bg-background px-2.5 py-1.5">
                <div className="text-2xs text-subtle">
                  {formatTs(e.timestamp)} · {e.source} · {e.event_id}
                </div>
                <code className="block whitespace-pre-wrap break-all font-mono text-2xs">{e.raw.length > 600 ? `${e.raw.slice(0, 600)}…` : e.raw}</code>
              </div>
            ))}
          </div>
        </Section>

        <Section n={8} title="Recommendations">
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            {r.recommendations.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ol>
        </Section>

        <Section n={9} title="LGPD notification">
          {r.lgpd.personal_data ? (
            <div className="space-y-2 text-sm">
              <p>
                Personal data was affected. The SOC became aware on <strong>{formatTs(r.lgpd.aware_at, { seconds: false })}</strong> (first detection).
              </p>
              <ul className="list-disc space-y-1 pl-5">
                <li>
                  Notify the ANPD and the data subjects by <strong className="font-mono">{r.lgpd.anpd_deadline}</strong> (3 business days).
                </li>
                <li>
                  Complement the communication by <strong className="font-mono">{r.lgpd.complement_deadline}</strong> (20 business days).
                </li>
              </ul>
              <p className="text-xs text-muted">Basis: {r.lgpd.basis}.</p>
              <ul className="list-disc space-y-0.5 pl-5 text-xs text-muted">
                {r.lgpd.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </div>
          ) : r.lgpd.personal_data === false ? (
            <p className="text-sm text-muted">Assessed: no personal data affected; no ANPD communication required.</p>
          ) : (
            <p className="text-sm text-muted">
              Not assessed yet{r.lgpd.suggested ? ": customer data was involved in this incident, assess it on the incident page." : "."}
            </p>
          )}
        </Section>

        <Section n={10} title="Analyst notes & resolution">
          {r.notes.length ? (
            <ul className="space-y-2 text-sm">
              {r.notes.map((n) => (
                <li key={n.id}>
                  <span className="text-xs text-subtle">
                    {formatTs(n.created_at, { seconds: false })} · {n.author}
                  </span>
                  <p className="whitespace-pre-wrap">{n.body}</p>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted">No notes recorded.</p>
          )}
          {inc.resolution && (
            <div className="mt-3 rounded-sm border border-success/30 bg-success/8 p-3 text-sm">
              <strong className="text-success">Resolution: </strong>
              {inc.resolution}
            </div>
          )}
        </Section>
      </article>
    </>
  );
}

export default function Page() {
  return (
    <React.Suspense fallback={<Skeleton className="h-[70vh] w-full" />}>
      <ReportPage />
    </React.Suspense>
  );
}
