import {
  Activity,
  BellRing,
  BookOpenCheck,
  ChartNoAxesColumn,
  FileText,
  FlaskConical,
  Grid3x3,
  LayoutDashboard,
  ScrollText,
  Settings2,
  ShieldCheck,
  Upload,
  type LucideIcon,
} from "lucide-react";

import type { SystemStatus } from "@/lib/types";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Live figure shown next to the item, read from /system/status. */
  count?: (s: SystemStatus) => number | string | undefined;
}

export interface NavGroup {
  /** Stage of the detection pipeline this group belongs to; groups are listed in data-flow order. */
  stage?: number;
  section: string;
  items: NavItem[];
}

export const OVERVIEW: NavItem = { href: "/", label: "Overview", icon: LayoutDashboard };

export const NAV: NavGroup[] = [
  {
    stage: 1,
    section: "Ingest",
    items: [
      { href: "/import", label: "Data import", icon: Upload, count: (s) => s.counts.imports || undefined },
      { href: "/events", label: "Log explorer", icon: ScrollText, count: (s) => s.counts.events },
    ],
  },
  {
    stage: 2,
    section: "Detect",
    items: [
      { href: "/rules", label: "Detection rules", icon: BookOpenCheck, count: (s) => `${s.counts.rules_enabled}/${s.counts.rules}` },
      { href: "/mitre", label: "ATT&CK coverage", icon: Grid3x3 },
      { href: "/simulations", label: "Simulations", icon: FlaskConical, count: (s) => s.counts.simulation_runs || undefined },
    ],
  },
  {
    stage: 3,
    section: "Respond",
    items: [
      { href: "/alerts", label: "Alerts", icon: BellRing, count: (s) => s.counts.open_alerts },
      { href: "/incidents", label: "Incidents", icon: ShieldCheck, count: (s) => s.counts.open_incidents },
    ],
  },
  {
    stage: 4,
    section: "Report",
    items: [
      { href: "/reports", label: "Reports", icon: FileText },
      { href: "/metrics", label: "Metrics", icon: ChartNoAxesColumn },
    ],
  },
];

export const LAB_NAV: NavItem[] = [
  { href: "/activity", label: "Activity log", icon: Activity },
  { href: "/settings", label: "Lab settings", icon: Settings2 },
];

export const ALL_NAV: NavItem[] = [OVERVIEW, ...NAV.flatMap((g) => g.items), ...LAB_NAV];
