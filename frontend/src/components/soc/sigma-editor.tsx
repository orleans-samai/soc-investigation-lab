"use client";

import { CheckCircle2, Save } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";

import { SeverityBadge, Tag } from "@/components/soc/badges";
import { CodeBlock, MitreChip } from "@/components/soc/common";
import { Button } from "@/components/ui/button";
import { SheetContent } from "@/components/ui/overlays";
import { Label, Textarea } from "@/components/ui/primitives";
import { api, post } from "@/lib/api";
import type { RuleInfo, SigmaPreview } from "@/lib/types";
import { formatTs, humanize, nf } from "@/lib/utils";

export const SIGMA_TEMPLATE = `title: Encoded PowerShell launched by a user
description: PowerShell started with an encoded command line, outside the admin account.
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  filter_admin:
    User|startswith: 'adm.'
  condition: selection and not filter_admin
falsepositives:
  - Software deployment tools that wrap scripts in base64
level: high
tags:
  - attack.execution
  - attack.t1059.001
`;

/**
 * Write or edit a Sigma rule: validate compiles it and dry-runs it on the lab's events; save puts it in the
 * engine next to the built-in rules (and re-runs detection).
 */
export function SigmaEditor({ rule, onSaved }: { rule?: RuleInfo; onSaved: (rule: RuleInfo) => void }) {
  const [source, setSource] = React.useState(rule?.source ?? SIGMA_TEMPLATE);
  const [preview, setPreview] = React.useState<SigmaPreview | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState<"validate" | "save" | null>(null);

  async function validate() {
    setBusy("validate");
    try {
      setPreview(await post<SigmaPreview>("/rules/custom/validate", { source }));
      setError(null);
    } catch (e) {
      setPreview(null);
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function save() {
    setBusy("save");
    try {
      const saved = rule
        ? await api<RuleInfo>(`/rules/custom/${rule.id}`, { method: "PUT", body: JSON.stringify({ source }) })
        : await post<RuleInfo>("/rules/custom", { source });
      toast.success(`${saved.id} ${saved.name} ${rule ? "updated" : "added"}; detection re-ran`);
      onSaved(saved);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <SheetContent
      title={rule ? `Edit ${rule.id} (Sigma)` : "New Sigma rule"}
      description="Write a rule in the SIEM-neutral Sigma format; it runs in this lab and exports to any SIEM."
      className="max-w-3xl"
    >
      <div className="grid gap-4 p-5">
        <div className="space-y-1.5">
          <Label htmlFor="sigma-source">Sigma YAML</Label>
          <Textarea
            id="sigma-source"
            value={source}
            onChange={(e) => (setSource(e.target.value), setPreview(null))}
            spellCheck={false}
            rows={20}
            className="font-mono text-xs leading-relaxed"
          />
          <p className="text-2xs text-subtle">
            Supported: selections, lists, keywords, modifiers (contains, startswith, endswith, all, re, cidr, exists, gt/gte/lt/lte), wildcards,
            conditions with and / or / not / 1 of / all of, and an <code>event_count</code> or <code>value_count</code> correlation in a second
            document. Products: windows, linux, application.
          </p>
        </div>
        {error && (
          <p role="alert" className="rounded-md border border-critical/30 bg-critical/8 px-3 py-2 text-sm">
            {error}
          </p>
        )}
        <div className="flex flex-wrap gap-2">
          <Button loading={busy === "validate"} disabled={!source.trim()} onClick={validate}>
            <CheckCircle2 /> Validate & dry-run
          </Button>
          <Button variant="primary" loading={busy === "save"} disabled={!preview} onClick={save} title={preview ? undefined : "Validate first"}>
            <Save /> {rule ? "Save changes" : "Add to engine"}
          </Button>
        </div>

        {preview && (
          <section className="space-y-3 rounded-md border border-border bg-surface p-4" aria-label="Dry-run result">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold">{preview.rule.name}</span>
              <SeverityBadge severity={preview.rule.severity} />
              <Tag>{humanize(preview.rule.rule_type)}</Tag>
              {preview.rule.mitre.map((m) => (
                <MitreChip key={m.technique_id} refItem={m} compact />
              ))}
            </div>
            <p className="text-sm">
              Matches <strong className="font-mono">{nf.format(preview.matched_events)}</strong> stored event(s) and would raise{" "}
              <strong className="font-mono">{nf.format(preview.alert_count)}</strong> alert(s).
              {preview.matched_events === 0 && " Run a scenario that produces this activity, or check field names and logsource."}
            </p>
            <CodeBlock label="Compiled logic">{preview.rule.logic}</CodeBlock>
            {preview.sample.length > 0 && (
              <ul className="space-y-1 text-xs text-muted">
                {preview.sample.slice(0, 6).map((s, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="shrink-0 font-mono text-subtle">{formatTs(s.timestamp, { seconds: false })}</span>
                    <span className="truncate">{s.reason}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}
      </div>
    </SheetContent>
  );
}
