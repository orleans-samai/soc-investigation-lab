"use client";

import { BookOpen, ChevronDown, Play } from "lucide-react";
import * as React from "react";

import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger } from "@/components/ui/overlays";
import { Input, Tooltip } from "@/components/ui/primitives";
import { nf } from "@/lib/utils";

export const QUERY_EXAMPLES: { label: string; query: string }[] = [
  { label: "Failed logins by source IP", query: "outcome:failure | stats count by source_ip | head 10" },
  { label: "SSH failures against the bastion", query: "source:linux_auth action:logon_failed host:bastion-01" },
  { label: "Successful logons from outside the network", query: "action:logon_success NOT ip:10.10.*" },
  { label: "Encoded or downloading PowerShell", query: "cmd:*powershell* (cmd:*-enc* OR cmd:*download*)" },
  { label: "Account and group changes", query: "action:user_created OR action:group_member_added" },
  { label: "Who used sudo, and how often", query: "action:sudo_command | stats count by username, hostname" },
  { label: "RDP logons (type 10)", query: "action:logon_success logon_type=10 | sort -timestamp" },
  { label: "Events per host and source", query: "| stats count by hostname, event_source | head 20" },
];

const SYNTAX = (
  <div className="space-y-1.5">
    <p>
      <code>field:value</code> (case-insensitive, <code>*</code> wildcard) · <code>field!=v</code> · <code>&gt;</code> <code>&gt;=</code> <code>&lt;</code> <code>&lt;=</code>
    </p>
    <p>
      <code>AND</code> (implicit), <code>OR</code>, <code>NOT</code> / <code>-term</code>, parentheses, <code>&quot;free text&quot;</code>
    </p>
    <p>
      Pipes: <code>| stats count by f1, f2</code> · <code>| sort -field</code> · <code>| head 20</code>
    </p>
    <p>
      Aliases: user, host, ip, src, action, source, type, level, cmd, process, target, group. Quote values with <code>:</code> such as timestamps.
    </p>
  </div>
);

export function QueryBar({
  value,
  onRun,
  matched,
  scanned,
}: {
  value: string;
  onRun: (query: string) => void;
  matched?: number;
  scanned?: number;
}) {
  const [text, setText] = React.useState(value);
  React.useEffect(() => setText(value), [value]);

  return (
    <div>
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          onRun(text.trim());
        }}
      >
        <div className="relative min-w-72 flex-1">
          <span className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 font-mono text-xs text-primary">&gt;</span>
          <Input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="outcome:failure host:bastion-01 | stats count by source_ip"
            className="pl-6 font-mono text-xs"
            aria-label="Query"
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        <Button type="submit" variant="primary">
          <Play /> Run
        </Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button type="button">
              Examples <ChevronDown />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-96">
            <DropdownMenuLabel>Example queries</DropdownMenuLabel>
            {QUERY_EXAMPLES.map((ex) => (
              <DropdownMenuItem key={ex.query} className="h-auto flex-col items-start gap-0.5 py-1.5" onSelect={() => (setText(ex.query), onRun(ex.query))}>
                <span>{ex.label}</span>
                <code className="font-mono text-2xs text-subtle">{ex.query}</code>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
        <Tooltip content={SYNTAX} side="bottom" className="max-w-md">
          <Button type="button" variant="ghost" size="icon" aria-label="Query syntax">
            <BookOpen />
          </Button>
        </Tooltip>
      </form>
      {matched !== undefined && scanned !== undefined && (
        <p className="mt-2 text-xs text-subtle">
          {nf.format(matched)} result{matched === 1 ? "" : "s"} from {nf.format(scanned)} events scanned
        </p>
      )}
    </div>
  );
}

/** Builds a drill-down query from a stats row: keep the filter part, add field:value terms, drop the pipes. */
export function drillDown(query: string, row: Record<string, unknown>, columns: string[]): string {
  const base = query.split("|")[0].trim();
  const terms = columns
    .filter((c) => c !== "count")
    .map((c) => (row[c] === null || row[c] === undefined ? `NOT ${c}:*` : `${c}:"${String(row[c]).replace(/"/g, '\\"')}"`));
  return [base, ...terms].filter(Boolean).join(" ");
}
