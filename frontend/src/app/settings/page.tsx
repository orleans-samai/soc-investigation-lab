"use client";

import { Database, RotateCcw, ShieldAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import useSWR, { useSWRConfig } from "swr";

import { Tag } from "@/components/soc/badges";
import { KeyValue, PageHeader, tableCls } from "@/components/soc/common";
import { EntityLink } from "@/components/soc/investigation-context";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/overlays";
import { Panel, PanelHeader, Skeleton } from "@/components/ui/primitives";
import { post } from "@/lib/api";
import type { Asset, Identity, SystemStatus } from "@/lib/types";
import { cn, formatTs, nf } from "@/lib/utils";

interface Inventory {
  organization: string;
  domain: string;
  internal_networks: string[];
  privileged_groups: string[];
  assets: Asset[];
  identities: Identity[];
  maintenance_windows: { id: string; description: string; usernames: string[]; hosts: string[]; start: string; end: string }[];
}

export default function SettingsPage() {
  const router = useRouter();
  const { mutate: globalMutate } = useSWRConfig();
  const { data: status, mutate } = useSWR<SystemStatus>("/system/status");
  const { data: inv } = useSWR<Inventory>("/system/inventory");

  async function reset() {
    try {
      const r = await post<{ events: number; alerts: number }>("/system/reset?confirm=RESET");
      toast.success(`Lab reset: ${nf.format(r.events)} baseline events, ${r.alerts} alerts`);
      await globalMutate(() => true);
      mutate();
      router.push("/");
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  return (
    <>
      <PageHeader title="Lab Settings" description="Environment status, the asset & identity inventory used to enrich detections, and lab maintenance." />
      <div className="grid gap-4 xl:grid-cols-3">
        <div className="min-w-0 space-y-4">
          <Panel>
            <PanelHeader title="Environment" />
            <div className="p-4">
              {!status ? (
                <Skeleton className="h-40 w-full" />
              ) : (
                <KeyValue
                  items={[
                    ["Mode", <Tag key="m" className="text-medium">{status.mode_label}</Tag>],
                    ["Organization", status.organization],
                    ["Simulated clock", `${formatTs(status.clock)} UTC`],
                    ["Lab timezone", status.timezone],
                    ["Business hours", `${status.business_hours[0]}:00 - ${status.business_hours[1]}:00, Mon-Fri`],
                    ["Storage", `${status.storage.backend} (atomic writes)`],
                    ["Upload limit", `${status.limits.max_upload_mb} MB / ${nf.format(status.limits.max_import_lines)} lines`],
                    ["Version", status.version],
                  ]}
                />
              )}
              {status?.storage.recovered_collections.length ? (
                <p className="mt-3 flex items-start gap-2 rounded-md border border-high/30 bg-high/6 p-2 text-xs text-high">
                  <ShieldAlert className="size-3.5 shrink-0" /> Corrupted state files were quarantined at startup: {status.storage.recovered_collections.join(", ")}
                </p>
              ) : null}
            </div>
          </Panel>
          <Panel>
            <PanelHeader title="Data" />
            <div className="grid grid-cols-2 gap-px bg-border">
              {status &&
                Object.entries(status.counts).map(([k, v]) => (
                  <div key={k} className="bg-surface px-4 py-2.5">
                    <div className="text-[11px] capitalize text-muted">{k.replace(/_/g, " ")}</div>
                    <div className="font-mono text-base tabular-nums">{nf.format(v)}</div>
                  </div>
                ))}
            </div>
          </Panel>
          <Panel className="border-critical/30">
            <PanelHeader title="Danger zone" />
            <div className="space-y-3 p-4">
              <p className="text-[13px] text-muted">
                Reset the lab to the seed dataset. Imported logs, simulation runs, alerts, incidents, notes and rule tuning are permanently discarded.
              </p>
              <ConfirmDialog
                title="Reset the whole lab?"
                description="This wipes all investigation work and reloads the baseline dataset. It cannot be undone. Export any reports you want to keep first."
                confirmLabel="Reset lab"
                onConfirm={reset}
                trigger={
                  <Button variant="danger">
                    <RotateCcw /> Reset lab
                  </Button>
                }
              />
            </div>
          </Panel>
        </div>

        <div className="min-w-0 space-y-4 xl:col-span-2">
          <Panel className="overflow-hidden">
            <PanelHeader title="Asset inventory" description={inv ? `${inv.organization} · ${inv.domain} · internal ${inv.internal_networks.join(", ")}` : ""} actions={<Database className="size-4 text-subtle" />} />
            <div className="overflow-x-auto">
              <table className={tableCls.table}>
                <thead className={tableCls.head}>
                  <tr>
                    <th className={tableCls.th}>Host</th>
                    <th className={tableCls.th}>Role</th>
                    <th className={cn(tableCls.th, "hidden md:table-cell")}>OS</th>
                    <th className={tableCls.th}>IP</th>
                    <th className={tableCls.th}>Criticality</th>
                  </tr>
                </thead>
                <tbody>
                  {inv?.assets.map((a) => (
                    <tr key={a.hostname} className={tableCls.row}>
                      <td className={tableCls.td}>
                        <EntityLink kind="host" value={a.hostname} />
                      </td>
                      <td className={cn(tableCls.td, "text-muted")}>{a.role}</td>
                      <td className={cn(tableCls.td, "hidden text-muted md:table-cell")}>{a.os}</td>
                      <td className={cn(tableCls.td, "font-mono text-xs")}>{a.ip}</td>
                      <td className={tableCls.td}>
                        <Tag className={cn(a.criticality === "critical" && "text-critical", a.criticality === "high" && "text-high")}>{a.criticality}</Tag>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          <Panel className="overflow-hidden">
            <PanelHeader title="Identity inventory" description={inv ? `Privileged groups: ${inv.privileged_groups.join(", ")}` : ""} />
            <div className="overflow-x-auto">
              <table className={tableCls.table}>
                <thead className={tableCls.head}>
                  <tr>
                    <th className={tableCls.th}>Account</th>
                    <th className={tableCls.th}>Name</th>
                    <th className={cn(tableCls.th, "hidden md:table-cell")}>Department</th>
                    <th className={tableCls.th}>Type</th>
                    <th className={tableCls.th}>Privileged</th>
                  </tr>
                </thead>
                <tbody>
                  {inv?.identities.map((i) => (
                    <tr key={i.username} className={tableCls.row}>
                      <td className={tableCls.td}>
                        <EntityLink kind="user" value={i.username} />
                      </td>
                      <td className={cn(tableCls.td, "text-muted")}>{i.display_name}</td>
                      <td className={cn(tableCls.td, "hidden text-muted md:table-cell")}>{i.department}</td>
                      <td className={tableCls.td}>
                        <Tag>{i.type}</Tag>
                      </td>
                      <td className={tableCls.td}>{i.privileged ? <Tag className="text-high">yes</Tag> : <span className="text-xs text-subtle">no</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>
          <Panel>
            <PanelHeader title="Approved change windows" description="Used by rules to flag activity that matches planned maintenance" />
            <ul className="divide-y divide-border">
              {inv?.maintenance_windows.map((w) => (
                <li key={w.id + w.start} className="px-4 py-2.5 text-[13px]">
                  <span className="mr-2 font-mono text-xs text-primary">{w.id}</span>
                  {w.description}
                  <div className="text-xs text-muted">
                    {formatTs(w.start, { seconds: false })} - {formatTs(w.end, { seconds: false })} UTC · {w.usernames.join(", ")} on {w.hosts.join(", ")}
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>
    </>
  );
}
