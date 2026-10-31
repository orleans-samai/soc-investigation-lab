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

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

export const NAV: { section: string; items: NavItem[] }[] = [
  { section: "Overview", items: [{ href: "/", label: "Dashboard", icon: LayoutDashboard }] },
  {
    section: "Investigate",
    items: [
      { href: "/alerts", label: "Alerts", icon: BellRing },
      { href: "/incidents", label: "Incidents", icon: ShieldCheck },
      { href: "/events", label: "Log Explorer", icon: ScrollText },
    ],
  },
  {
    section: "Detect",
    items: [
      { href: "/rules", label: "Detection Rules", icon: BookOpenCheck },
      { href: "/mitre", label: "MITRE ATT&CK", icon: Grid3x3 },
      { href: "/simulations", label: "Simulations", icon: FlaskConical },
    ],
  },
  {
    section: "Report",
    items: [
      { href: "/reports", label: "Reports", icon: FileText },
      { href: "/metrics", label: "Metrics", icon: ChartNoAxesColumn },
    ],
  },
  {
    section: "Lab",
    items: [
      { href: "/import", label: "Data Import", icon: Upload },
      { href: "/activity", label: "Activity Log", icon: Activity },
      { href: "/settings", label: "Lab Settings", icon: Settings2 },
    ],
  },
];

export const ALL_NAV = NAV.flatMap((s) => s.items);
