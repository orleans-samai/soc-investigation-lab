"use client";

import { AlertTriangle, CheckCircle2, FileUp, FileWarning, ShieldCheck, Upload, X } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";
import useSWR from "swr";

import { KeyValue, PageHeader, tableCls, Term } from "@/components/soc/common";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/overlays";
import { Input, Label, Panel, PanelHeader } from "@/components/ui/primitives";
import { api } from "@/lib/api";
import type { ImportRecord, ImportReport, LogFormat, SystemStatus } from "@/lib/types";
import { cn, formatBytes, formatTs, humanize, nf, relative } from "@/lib/utils";
import { incidentHref } from "@/lib/routes";

const FORMATS: { value: LogFormat; label: string }[] = [
  { value: "auto", label: "Auto-detect" },
  { value: "windows_json", label: "Windows events (JSON / NDJSON)" },
  { value: "linux_ssh", label: "Linux auth.log / secure (syslog)" },
  { value: "normalized_json", label: "Normalized lab schema (JSON)" },
];

const TIMEZONES = ["UTC", "America/Sao_Paulo", "America/New_York", "Europe/London", "Europe/Lisbon", "Asia/Tokyo"];

const SAMPLES = [
  { file: "windows_security_sample.json", label: "Windows Security events", note: "4625 burst + 4624, JSON array" },
  { file: "sysmon_sample.json", label: "Sysmon events", note: "LSASS access (one benign, one malicious) + phishing DNS" },
  { file: "linux_auth_sample.log", label: "Linux auth.log", note: "Classic syslog, needs year + timezone" },
  { file: "normalized_sample.json", label: "Normalized events", note: "Lab schema, as exported by the Log Explorer" },
  { file: "malformed_sample.log", label: "Malformed file", note: "Shows per-line error reporting" },
];

export default function ImportPage() {
  const { data: status } = useSWR<SystemStatus>("/system/status");
  const { data: history, mutate: refreshHistory } = useSWR<ImportRecord[]>("/imports");
  const [file, setFile] = React.useState<File | null>(null);
  const [format, setFormat] = React.useState<LogFormat>("auto");
  const [timezone, setTimezone] = React.useState("UTC");
  const [year, setYear] = React.useState(String(new Date().getUTCFullYear()));
  const [report, setReport] = React.useState<ImportReport | null>(null);
  const [busy, setBusy] = React.useState<"validate" | "import" | null>(null);
  const [dragging, setDragging] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement>(null);
  const maxMb = status?.limits.max_upload_mb ?? 5;

  function choose(f: File | undefined | null) {
    setReport(null);
    if (!f) return;
    if (f.size > maxMb * 1024 * 1024) {
      toast.error(`${f.name} is ${formatBytes(f.size)}; the limit is ${maxMb} MB`);
      return;
    }
    setFile(f);
  }

  async function send(dryRun: boolean) {
    if (!file) return;
    const body = new FormData();
    body.append("file", file);
    body.append("format", format);
    body.append("timezone", timezone);
    if (year) body.append("year", year);
    body.append("dry_run", String(dryRun));
    setBusy(dryRun ? "validate" : "import");
    try {
      const result = await api<ImportReport>("/imports", { method: "POST", body });
      setReport(result);
      if (!dryRun) {
        toast.success(`Imported ${nf.format(result.added)} events · ${result.alerts_created} new alert(s)`);
        refreshHistory();
      }
    } catch (e) {
      setReport(null);
      toast.error((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  const committed = report && !report.dry_run;

  return (
    <>
      <PageHeader
        title="Data Import"
        description={
          <>
            Upload Windows or Linux logs. Files are validated first: nothing is stored until you confirm, duplicates are detected by content hash, and
            invalid lines are reported individually. Content is only ever parsed as text - <Term name="Fail-safe import">never executed</Term>.
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="min-w-0 space-y-4 xl:col-span-2">
          <Panel>
            <PanelHeader title="1. Choose a file" description={`JSON, NDJSON, .log or .txt - up to ${maxMb} MB / ${nf.format(status?.limits.max_import_lines ?? 50000)} lines`} />
            <div className="p-4">
              <div
                role="button"
                tabIndex={0}
                onClick={() => inputRef.current?.click()}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && inputRef.current?.click()}
                onDragOver={(e) => (e.preventDefault(), setDragging(true))}
                onDragLeave={() => setDragging(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragging(false);
                  choose(e.dataTransfer.files[0]);
                }}
                className={cn(
                  "flex cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed border-border-strong px-6 py-10 text-center transition-colors hover:border-primary/60 hover:bg-primary/4",
                  dragging && "border-primary bg-primary/8",
                )}
              >
                <FileUp className="mb-2 size-6 text-subtle" />
                {file ? (
                  <>
                    <p className="text-[13px] font-medium">{file.name}</p>
                    <p className="text-xs text-muted">{formatBytes(file.size)} · click to choose another file</p>
                  </>
                ) : (
                  <>
                    <p className="text-[13px] font-medium">Drop a log file here, or click to browse</p>
                    <p className="text-xs text-muted">Try one of the sample files on the right</p>
                  </>
                )}
                <input
                  ref={inputRef}
                  type="file"
                  accept=".json,.ndjson,.jsonl,.log,.txt,application/json,text/plain"
                  className="sr-only"
                  onChange={(e) => choose(e.target.files?.[0])}
                />
              </div>

              <div className="mt-4 grid gap-3 sm:grid-cols-3">
                <div className="space-y-1">
                  <Label>Format</Label>
                  <Select aria-label="Format" className="w-full" value={format} onValueChange={(v) => (setFormat(v as LogFormat), setReport(null))} options={FORMATS} />
                </div>
                <div className="space-y-1">
                  <Label>Timezone for timestamps without offset</Label>
                  <Select aria-label="Timezone" className="w-full" value={timezone} onValueChange={(v) => (setTimezone(v), setReport(null))} options={TIMEZONES.map((t) => ({ value: t, label: t }))} />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="year">Year for classic syslog lines</Label>
                  <Input id="year" inputMode="numeric" value={year} onChange={(e) => (setYear(e.target.value.replace(/\D/g, "").slice(0, 4)), setReport(null))} />
                </div>
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-2">
                <Button variant="primary" disabled={!file} loading={busy === "validate"} onClick={() => send(true)}>
                  <ShieldCheck /> Validate file
                </Button>
                {file && (
                  <Button variant="ghost" onClick={() => (setFile(null), setReport(null))}>
                    <X /> Clear
                  </Button>
                )}
                <span className="text-xs text-subtle">Validation is a dry run: it parses everything and shows what would be imported.</span>
              </div>
            </div>
          </Panel>

          {report && (
            <Panel className="animate-in">
              <PanelHeader
                title={committed ? "Import complete" : "2. Review validation report"}
                description={`${report.filename} · detected format: ${humanize(report.format)}`}
                actions={
                  !committed && (
                    <Button variant="primary" disabled={report.added === 0} loading={busy === "import"} onClick={() => send(false)}>
                      <Upload /> Import {nf.format(report.added)} events
                    </Button>
                  )
                }
              />
              <div className="grid grid-cols-2 gap-px border-b border-border bg-border sm:grid-cols-5">
                {[
                  ["Records", report.total_records, ""],
                  ["Parsed", report.parsed, ""],
                  [committed ? "Added" : "New", report.added, "text-success"],
                  ["Duplicates", report.duplicates, report.duplicates ? "text-medium" : ""],
                  ["Errors", report.error_count, report.error_count ? "text-critical" : ""],
                ].map(([label, value, tone]) => (
                  <div key={label as string} className="bg-surface px-4 py-3">
                    <div className="text-xs text-muted">{label}</div>
                    <div className={cn("mt-1 font-mono text-lg tabular-nums", tone as string)}>{nf.format(value as number)}</div>
                  </div>
                ))}
              </div>
              <div className="space-y-4 p-4">
                {committed ? (
                  <div className="flex items-start gap-3 rounded-md border border-success/30 bg-success/6 p-3 text-[13px]">
                    <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" />
                    <div>
                      {nf.format(report.added)} events stored and the detection engine re-ran: <strong>{report.alerts_created}</strong> new alert(s).
                      {report.incidents_touched.length > 0 && (
                        <span>
                          {" "}
                          Incidents updated:{" "}
                          {report.incidents_touched.map((id) => (
                            <Link key={id} href={incidentHref(id)} className="mr-1 font-mono text-primary hover:underline">
                              {id}
                            </Link>
                          ))}
                        </span>
                      )}
                      <div className="mt-2 flex gap-2">
                        <Button asChild size="sm">
                          <Link href={`/events?dataset=import:${report.filename}`}>View imported events</Link>
                        </Button>
                        <Button asChild size="sm" variant="ghost">
                          <Link href="/alerts">Alert queue</Link>
                        </Button>
                      </div>
                    </div>
                  </div>
                ) : report.added === 0 ? (
                  <div className="flex items-start gap-3 rounded-md border border-medium/30 bg-medium/6 p-3 text-[13px]">
                    <AlertTriangle className="mt-0.5 size-4 shrink-0 text-medium" />
                    Nothing new to import{report.duplicates ? " - every valid record is already in the lab" : ""}.
                  </div>
                ) : null}

                <KeyValue
                  items={[
                    ["Time range (UTC)", report.first_timestamp ? `${formatTs(report.first_timestamp)} - ${formatTs(report.last_timestamp)}` : "-"],
                    ["Skipped", `${nf.format(report.skipped)} valid records of event types the lab does not model`],
                    ["File size", formatBytes(report.size_bytes)],
                  ]}
                />

                {report.errors.length > 0 && (
                  <div>
                    <h3 className="mb-2 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-subtle">
                      <FileWarning className="size-3.5" /> Parsing errors
                      {report.error_count > report.errors.length && ` (first ${report.errors.length} of ${report.error_count})`}
                    </h3>
                    <div className="max-h-64 overflow-auto rounded-md border border-border">
                      <table className={tableCls.table}>
                        <thead className={tableCls.head}>
                          <tr>
                            <th className={cn(tableCls.th, "w-16")}>Line</th>
                            <th className={tableCls.th}>Problem</th>
                            <th className={tableCls.th}>Excerpt</th>
                          </tr>
                        </thead>
                        <tbody>
                          {report.errors.map((err, i) => (
                            <tr key={i} className={tableCls.row}>
                              <td className="px-3 py-1.5 font-mono text-xs text-muted">{err.line ?? "-"}</td>
                              <td className="px-3 py-1.5 text-xs text-critical">{err.message}</td>
                              <td className="max-w-0 px-3 py-1.5">
                                <code className="block truncate font-mono text-[11px] text-muted">{err.excerpt}</code>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {report.preview.length > 0 && !committed && (
                  <div>
                    <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-subtle">Preview (first {report.preview.length} normalized events)</h3>
                    <div className="max-h-72 overflow-auto rounded-md border border-border">
                      <table className={tableCls.table}>
                        <thead className={tableCls.head}>
                          <tr>
                            <th className={tableCls.th}>Timestamp (UTC)</th>
                            <th className={tableCls.th}>Action</th>
                            <th className={tableCls.th}>Host</th>
                            <th className={tableCls.th}>User</th>
                            <th className={tableCls.th}>Source IP</th>
                          </tr>
                        </thead>
                        <tbody>
                          {report.preview.map((e) => (
                            <tr key={e.id} className={tableCls.row}>
                              <td className="whitespace-nowrap px-3 py-1.5 font-mono text-xs text-muted">{formatTs(e.timestamp)}</td>
                              <td className={cn("px-3 py-1.5 text-xs", e.outcome === "failure" && "text-high")}>{e.event_action}</td>
                              <td className="px-3 py-1.5 text-xs">{e.hostname}</td>
                              <td className="px-3 py-1.5 text-xs">{e.username ?? "-"}</td>
                              <td className="px-3 py-1.5 font-mono text-xs">{e.source_ip ?? "-"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </Panel>
          )}
        </div>

        <div className="min-w-0 space-y-4">
          <Panel>
            <PanelHeader title="Sample files" description="Download, then upload them here" />
            <ul className="divide-y divide-border">
              {SAMPLES.map((s) => (
                <li key={s.file} className="flex items-center gap-3 px-4 py-2.5">
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px]">{s.label}</div>
                    <div className="truncate text-xs text-subtle">{s.note}</div>
                  </div>
                  <Button asChild size="sm" variant="ghost">
                    <a href={`/samples/${s.file}`} download>
                      Download
                    </a>
                  </Button>
                </li>
              ))}
            </ul>
          </Panel>
          <Panel>
            <PanelHeader title="Supported formats" />
            <div className="space-y-3 p-4 text-xs leading-relaxed text-muted">
              <p>
                <strong className="text-foreground">Windows</strong> - JSON array, NDJSON or <code>{"{ events: [...] }"}</code> with <code>EventID</code>, <code>TimeCreated</code>,{" "}
                <code>Computer</code>, <code>EventData</code>. Mapped IDs: 4624, 4625, 4634, 4672, 4688, 4697, 4698, 4720, 4722, 4724, 4726, 4728, 4732, 4740, 4756, 1102, 4104, 7045, plus Sysmon 1, 3, 10, 11 and 22 (Channel Microsoft-Windows-Sysmon/Operational).
              </p>
              <p>
                <strong className="text-foreground">Linux</strong> - auth.log/secure lines from sshd, sudo, su, useradd, usermod, gpasswd, groupadd, cron and systemd-logind, in classic
                (<code>Oct 30 14:02:11</code>) or RFC 3339 syslog format.
              </p>
              <p>
                <strong className="text-foreground">Normalized</strong> - the lab&apos;s own schema (<code>event_source</code>, <code>event_action</code>, <code>raw</code>...). IDs are recomputed
                from the raw record so duplicates cannot be smuggled in.
              </p>
            </div>
          </Panel>
          <Panel>
            <PanelHeader title="Import history" />
            {history?.length ? (
              <ul className="divide-y divide-border">
                {history.slice(0, 8).map((h) => (
                  <li key={h.id} className="px-4 py-2.5 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-[13px]">{h.filename}</span>
                      <span className="shrink-0 text-subtle">{relative(h.created_at)}</span>
                    </div>
                    <div className="mt-0.5 text-muted">
                      +{nf.format(h.added)} events · {h.duplicates} dup · {h.error_count} errors · {h.alerts_created} alerts
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="px-4 py-6 text-center text-xs text-muted">No files imported yet.</p>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}
