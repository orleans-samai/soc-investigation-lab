"use client";

import { FlaskConical, Play, RotateCw, Save } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";
import useSWR from "swr";

import { SeverityBadge, Tag } from "@/components/soc/badges";
import { CodeBlock, MitreChip, PageHeader, Term } from "@/components/soc/common";
import { Button } from "@/components/ui/button";
import { Input, Label, Panel, PanelHeader, Skeleton, Switch } from "@/components/ui/primitives";
import { patch, post } from "@/lib/api";
import type { BacktestResult, RuleInfo } from "@/lib/types";
import { useUrlState } from "@/lib/use-url-state";
import { cn, formatTs, humanize, nf, relative } from "@/lib/utils";

function RuleDetail({ rule, onChanged }: { rule: RuleInfo; onChanged: () => void }) {
  const [params, setParams] = React.useState<Record<string, number>>({});
  const [backtest, setBacktest] = React.useState<BacktestResult | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);
  React.useEffect(() => {
    setParams(Object.fromEntries(rule.params.map((p) => [p.name, p.value])));
    setBacktest(null);
  }, [rule.id, rule.params]);

  const dirty = rule.params.some((p) => params[p.name] !== p.value);
  const invalid = rule.params.some((p) => !(params[p.name] >= p.min && params[p.name] <= p.max));

  async function run<T>(label: string, fn: () => Promise<T>) {
    setBusy(label);
    try {
      return await fn();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <Panel className="xl:sticky xl:top-16">
      <PanelHeader
        title={
          <span className="flex items-center gap-2">
            <span className="font-mono text-xs text-subtle">{rule.id}</span> {rule.name}
          </span>
        }
        description={`${humanize(rule.rule_type)} rule · data: ${rule.data_sources.join(", ")}`}
        actions={
          <label className="flex items-center gap-2 text-xs text-muted">
            {rule.enabled ? "Enabled" : "Disabled"}
            <Switch
              checked={rule.enabled}
              aria-label={`Enable ${rule.name}`}
              onCheckedChange={(enabled) =>
                run("toggle", async () => {
                  await patch(`/rules/${rule.id}`, { enabled });
                  toast.success(`${rule.id} ${enabled ? "enabled" : "disabled"}`);
                  onChanged();
                })
              }
            />
          </label>
        }
      />
      <div className="space-y-5 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={rule.severity} />
          {rule.mitre.map((m) => (
            <MitreChip key={m.technique_id} refItem={m} />
          ))}
        </div>
        <p className="text-[13px] leading-relaxed text-muted">{rule.description}</p>

        <section>
          <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-subtle">Logic</h3>
          <CodeBlock>{rule.logic}</CodeBlock>
        </section>

        {rule.params.length > 0 && (
          <section>
            <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-subtle">
              Tuning - <Term name="Threshold">thresholds</Term> & windows
            </h3>
            <p className="mb-3 text-xs text-muted">
              Change a value and <Term name="Backtest">backtest</Term> it against all stored events before saving. Saved values apply to future detection runs.
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              {rule.params.map((p) => (
                <div key={p.name} className="space-y-1">
                  <Label htmlFor={p.name}>
                    {p.label} {p.unit && <span className="text-subtle">({p.unit})</span>}
                  </Label>
                  <Input
                    id={p.name}
                    type="number"
                    min={p.min}
                    max={p.max}
                    value={Number.isNaN(params[p.name]) ? "" : params[p.name] ?? ""}
                    onChange={(e) => (setParams((s) => ({ ...s, [p.name]: e.target.valueAsNumber })), setBacktest(null))}
                    className="font-mono"
                    aria-describedby={`${p.name}-range`}
                  />
                  <p id={`${p.name}-range`} className="text-[11px] text-subtle">
                    Allowed {p.min}-{p.max}
                  </p>
                </div>
              ))}
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button
                disabled={invalid}
                loading={busy === "backtest"}
                onClick={() => run("backtest", async () => setBacktest(await post<BacktestResult>(`/rules/${rule.id}/backtest`, { params })))}
              >
                <FlaskConical /> Backtest
              </Button>
              <Button
                variant="primary"
                disabled={!dirty || invalid}
                loading={busy === "save"}
                onClick={() =>
                  run("save", async () => {
                    await patch(`/rules/${rule.id}`, { params });
                    const r = await post<{ new_alerts: number }>("/detection/run");
                    toast.success(`Saved. Detection re-ran: ${r.new_alerts} new alert(s)`);
                    onChanged();
                  })
                }
              >
                <Save /> Save & re-run
              </Button>
            </div>
            {backtest && (
              <div className="mt-3 rounded-md border border-border bg-surface-2/60 p-3 text-[13px]">
                <p>
                  With these values the rule would produce <strong className="font-mono">{backtest.alert_count}</strong> alert(s) on the current dataset (currently{" "}
                  <span className="font-mono">{backtest.current_alert_count}</span>).
                  {backtest.alert_count > backtest.current_alert_count ? " More sensitive - expect more noise." : backtest.alert_count < backtest.current_alert_count ? " Stricter - check you are not hiding real attacks." : ""}
                </p>
                {backtest.sample.length > 0 && (
                  <ul className="mt-2 space-y-1 text-xs text-muted">
                    {backtest.sample.slice(0, 5).map((s, i) => (
                      <li key={i} className="flex gap-2">
                        <span className="shrink-0 font-mono text-subtle">{formatTs(s.timestamp, { seconds: false })}</span>
                        <span className="truncate">{s.reason}</span>
                        {!s.existing && <Tag className="ml-auto shrink-0 text-primary">new</Tag>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </section>
        )}

        <section className="grid gap-4 sm:grid-cols-2">
          <div>
            <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wide text-subtle">Known false positives</h3>
            <ul className="list-disc space-y-1 pl-4 text-[13px] text-muted">
              {rule.false_positives.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wide text-subtle">Response</h3>
            <ol className="list-decimal space-y-1 pl-4 text-[13px] text-muted">
              {rule.response.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </div>
        </section>
        <div className="flex items-center justify-between border-t border-border pt-3 text-xs text-muted">
          <span>
            {nf.format(rule.alert_count)} alert(s) · last triggered {rule.last_triggered ? relative(rule.last_triggered) : "never"}
          </span>
          <Button asChild size="sm" variant="ghost">
            <Link href={`/alerts?rule_id=${rule.id}&status=`}>View alerts</Link>
          </Button>
        </div>
      </div>
    </Panel>
  );
}

function Rules() {
  const [f, set] = useUrlState({ rule: "" });
  const { data: rules, mutate } = useSWR<RuleInfo[]>("/rules");
  const [rerunning, setRerunning] = React.useState(false);
  const selected = rules?.find((r) => r.id === f.rule) ?? rules?.[0];

  return (
    <>
      <PageHeader
        title="Detection Rules"
        description="The Python detection engine evaluates these rules over normalized events. Each rule is unit-tested, mapped to MITRE ATT&CK and documents its false positives and response steps."
        actions={
          <Button
            loading={rerunning}
            onClick={async () => {
              setRerunning(true);
              try {
                const r = await post<{ new_alerts: number; updated_alerts: number }>("/detection/run");
                toast.success(`Detection complete: ${r.new_alerts} new, ${r.updated_alerts} updated alert(s)`);
                mutate();
              } catch (e) {
                toast.error((e as Error).message);
              } finally {
                setRerunning(false);
              }
            }}
          >
            <RotateCw /> Re-run detection
          </Button>
        }
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <Panel className="h-fit overflow-hidden">
          <PanelHeader title={`${rules?.length ?? "-"} rules`} description={`${rules?.filter((r) => r.enabled).length ?? "-"} enabled`} />
          <ul className="divide-y divide-border">
            {!rules &&
              Array.from({ length: 8 }).map((_, i) => (
                <li key={i} className="p-3">
                  <Skeleton className="h-9 w-full" />
                </li>
              ))}
            {rules?.map((r) => (
              <li key={r.id}>
                <button
                  onClick={() => set({ rule: r.id })}
                  aria-current={selected?.id === r.id}
                  className={cn(
                    "flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-surface-2",
                    selected?.id === r.id && "bg-surface-2 shadow-[inset_2px_0_0_var(--primary)]",
                    !r.enabled && "opacity-55",
                  )}
                >
                  <span className="w-16 shrink-0 font-mono text-[11px] text-subtle">{r.id}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[13px] font-medium">{r.name}</span>
                    <span className="block truncate text-[11px] text-subtle">{r.mitre.map((m) => m.technique_id).join(" · ")}</span>
                  </span>
                  <SeverityBadge severity={r.severity} className="hidden sm:inline-flex" />
                  <span className="w-8 text-right font-mono text-xs tabular-nums text-muted" title="Alerts">
                    {r.alert_count}
                  </span>
                  {!r.enabled && <Tag>off</Tag>}
                </button>
              </li>
            ))}
          </ul>
        </Panel>
        {selected ? (
          <RuleDetail rule={selected} onChanged={() => mutate()} />
        ) : (
          <Skeleton className="h-96 w-full" />
        )}
      </div>
      <p className="mt-4 flex items-center gap-1.5 text-xs text-subtle">
        <Play className="size-3" /> Tip: run a scenario in <Link href="/simulations" className="text-primary hover:underline">Simulations</Link> to see each rule fire end-to-end.
      </p>
    </>
  );
}

export default function RulesPage() {
  return (
    <React.Suspense fallback={<Skeleton className="h-96 w-full" />}>
      <Rules />
    </React.Suspense>
  );
}
