import {
  IconArrowUpRight,
  IconCircleCheck,
  IconCircleDot,
  IconCircleX,
  IconClock,
} from "@tabler/icons-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge as UiBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type Severity = "high" | "medium" | "low" | "info";
type ScanStatus = "completed" | "running" | "failed" | "queued";

interface MockScan {
  id: string;
  target: string;
  profile: "active" | "passive";
  status: ScanStatus;
  findings: number;
  ago: string;
  error?: string;
}

const mockScans: MockScan[] = [
  {
    id: "wp-001",
    target: "staging.example.com",
    profile: "active",
    status: "completed",
    findings: 36,
    ago: "2 min ago",
  },
  {
    id: "wp-002",
    target: "api.acme.dev",
    profile: "passive",
    status: "running",
    findings: 0,
    ago: "12 min ago",
  },
  {
    id: "wp-003",
    target: "shop.example.com",
    profile: "active",
    status: "failed",
    findings: 0,
    ago: "1 hr ago",
    error: "ScopeController rejected host",
  },
  {
    id: "wp-004",
    target: "auth.example.com",
    profile: "passive",
    status: "completed",
    findings: 12,
    ago: "3 hr ago",
  },
  {
    id: "wp-005",
    target: "cdn.example.com",
    profile: "active",
    status: "queued",
    findings: 0,
    ago: "5 hr ago",
  },
];

const stats = [
  {
    label: "Total scans",
    value: "1,284",
    trend: "+12 this week",
    trendUp: true,
  },
  {
    label: "Active targets",
    value: "37",
    trend: "+2 this week",
    trendUp: true,
  },
  {
    label: "Findings (7d)",
    value: "412",
    trend: "-18 vs last week",
    trendUp: false,
  },
];

function statusVariant(status: ScanStatus) {
  switch (status) {
    case "completed":
      return {
        className: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
        label: "completed",
        Icon: IconCircleCheck,
      };
    case "running":
      return {
        className: "bg-sky-500/10 text-sky-400 border-sky-500/20",
        label: "running",
        Icon: IconCircleDot,
      };
    case "failed":
      return {
        className: "bg-red-500/10 text-red-400 border-red-500/20",
        label: "failed",
        Icon: IconCircleX,
      };
    case "queued":
    default:
      return {
        className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
        label: "queued",
        Icon: IconClock,
      };
  }
}

export default function DashboardPage() {
  return (
    <div className="space-y-10">
      {/* Header */}
      <header className="space-y-2">
        <h1 className="font-serif text-4xl font-bold tracking-tight text-zinc-100">
          Dashboard
        </h1>
        <p className="text-sm text-zinc-400">
          Workspace overview, recent activity, and quick actions.
        </p>
      </header>

      {/* Stat cards */}
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {stats.map((s) => (
          <Card
            key={s.label}
            className="rounded-xl border border-zinc-800 bg-zinc-900"
          >
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">
                {s.label}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <div className="text-3xl font-bold text-zinc-100">{s.value}</div>
              <div
                className={cn(
                  "flex items-center gap-1 text-xs",
                  s.trendUp ? "text-emerald-400" : "text-red-400",
                )}
              >
                <IconArrowUpRight
                  size={12}
                  className={cn(!s.trendUp && "rotate-180")}
                />
                {s.trend}
              </div>
            </CardContent>
          </Card>
        ))}
      </section>

      {/* Recent activity */}
      <section className="space-y-4">
        <div className="flex items-baseline justify-between">
          <h2 className="text-lg font-semibold text-zinc-100">
            Recent activity
          </h2>
          <span className="text-xs text-zinc-500">Last 24 hours</span>
        </div>

        <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
          <ul className="divide-y divide-zinc-800">
            {mockScans.map((scan) => {
              const v = statusVariant(scan.status);
              return (
                <li
                  key={scan.id}
                  className="flex items-center gap-4 px-5 py-4 hover:bg-zinc-900/60"
                >
                  <span className="font-mono text-xs text-zinc-500">
                    {scan.id}
                  </span>
                  <span className="flex-1 truncate font-mono text-sm text-zinc-200">
                    {scan.target}
                  </span>
                  <span className="hidden text-xs text-zinc-500 sm:inline">
                    {scan.profile}
                  </span>
                  <span className="hidden font-mono text-xs text-zinc-400 sm:inline">
                    {scan.findings} findings
                  </span>
                  <UiBadge
                    variant="outline"
                    className={cn("gap-1 border", v.className)}
                  >
                    <v.Icon size={12} />
                    {v.label}
                  </UiBadge>
                  <span className="w-20 text-right text-xs text-zinc-500">
                    {scan.ago}
                  </span>
                </li>
              );
            })}
          </ul>
        </Card>
      </section>
    </div>
  );
}