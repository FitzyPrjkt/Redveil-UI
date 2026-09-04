"use client";

import { useEffect, useMemo, useState } from "react";
import {
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
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";

type ScanStatus = "pending" | "running" | "completed" | "failed";

interface Scan {
  id: number;
  target_id: number;
  status: string;
  profile: string;
  scan_type: string;
  started_at: string | null;
  completed_at: string | null;
  total_requests: number;
  error: string | null;
}

interface Target {
  id: number;
  url: string;
}

interface Finding {
  id: number;
  scan_id: number;
  wpoc_id: string;
  severity: string;
  status: string;
  title: string;
  created_at: string;
}

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const delta = Date.now() - t;
  const s = Math.floor(delta / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} hour${h === 1 ? "" : "s"} ago`;
  const d = Math.floor(h / 24);
  return `${d} day${d === 1 ? "" : "s"} ago`;
}

function statusVariant(status: string) {
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
    case "pending":
    default:
      return {
        className: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
        label: status,
        Icon: IconClock,
      };
  }
}

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      apiGet<Scan[]>("/api/scans?limit=500"),
      apiGet<Target[]>("/api/targets"),
      apiGet<Finding[]>("/api/findings?limit=500"),
    ])
      .then(([s, t, f]) => {
        setScans(s);
        setTargets(t);
        setFindings(f);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err));
      });
  }, []);

  // Build target-id → URL map so the activity list can show the URL
  // next to the scan id.
  const targetById = useMemo(() => {
    const map = new Map<number, string>();
    targets?.forEach((t) => map.set(t.id, t.url));
    return map;
  }, [targets]);

  // Findings (7d) — count of findings created within the last 7 days.
  const findings7d = useMemo(() => {
    if (!findings) return 0;
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    return findings.filter((f) => {
      const t = new Date(f.created_at).getTime();
      return Number.isFinite(t) && t >= sevenDaysAgo;
    }).length;
  }, [findings]);

  // Top 10 most-recent scans for the activity list.
  const recentScans = useMemo(() => {
    if (!scans) return [];
    return [...scans]
      .sort((a, b) => {
        const at = new Date(a.started_at ?? 0).getTime();
        const bt = new Date(b.started_at ?? 0).getTime();
        return bt - at;
      })
      .slice(0, 10);
  }, [scans]);

  return (
    <div className="space-y-10" data-testid="dashboard">
      {/* Header */}
      <header className="space-y-2">
        <h1 className="font-serif text-4xl font-bold tracking-tight text-zinc-100">
          Dashboard
        </h1>
        <p className="text-sm text-zinc-400">
          Workspace overview, recent activity, and quick actions.
        </p>
      </header>

      {error ? (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
        >
          Failed to load dashboard data: {error}
        </div>
      ) : null}

      {/* Stat cards */}
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <StatTile
          label="Total scans"
          testId="stat-total-scans"
          value={scans === null ? null : String(scans.length)}
        />
        <StatTile
          label="Active targets"
          testId="stat-active-targets"
          value={targets === null ? null : String(targets.length)}
        />
        <StatTile
          label="Findings (7d)"
          testId="stat-findings-7d"
          value={findings === null ? null : String(findings7d)}
        />
      </section>

      {/* Recent activity */}
      <section className="space-y-4">
        <div className="flex items-baseline justify-between">
          <h2 className="text-lg font-semibold text-zinc-100">
            Recent activity
          </h2>
          <span className="text-xs text-zinc-500">Last 24 hours</span>
        </div>

        {scans === null ? (
          <div data-testid="activity-loading" className="space-y-1">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
        ) : recentScans.length === 0 ? (
          <div
            role="status"
            data-testid="activity-empty"
            className="rounded-xl border border-zinc-800 bg-zinc-900 p-8 text-center text-sm text-zinc-500"
          >
            No scans yet. Start one from Targets → New Scan.
          </div>
        ) : (
          <Card
            data-testid="activity-list"
            className="rounded-xl border border-zinc-800 bg-zinc-900"
          >
            <ul className="divide-y divide-zinc-800">
              {recentScans.map((scan) => {
                const v = statusVariant(scan.status);
                const targetUrl = targetById.get(scan.target_id) ?? "—";
                return (
                  <li
                    key={scan.id}
                    data-testid="activity-row"
                    className="flex items-center gap-4 px-5 py-4 hover:bg-zinc-900/60"
                  >
                    <span className="font-mono text-xs text-zinc-500">
                      scan #{scan.id}
                    </span>
                    <span className="flex-1 truncate font-mono text-sm text-zinc-200">
                      {targetUrl}
                    </span>
                    <span className="hidden text-xs text-zinc-500 sm:inline">
                      {scan.profile}
                    </span>
                    <span className="hidden font-mono text-xs text-zinc-400 sm:inline">
                      {scan.total_requests} reqs
                    </span>
                    <UiBadge
                      variant="outline"
                      className={cn("gap-1 border", v.className)}
                    >
                      <v.Icon size={12} />
                      {v.label}
                    </UiBadge>
                    <span className="w-20 text-right text-xs text-zinc-500">
                      {timeAgo(scan.started_at)}
                    </span>
                  </li>
                );
              })}
            </ul>
          </Card>
        )}
      </section>
    </div>
  );
}

function StatTile({
  label,
  testId,
  value,
}: {
  label: string;
  testId: string;
  value: string | null;
}) {
  return (
    <Card
      data-testid={testId}
      className="rounded-xl border border-zinc-800 bg-zinc-900"
    >
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1">
        {value === null ? (
          <Skeleton className="h-9 w-24" />
        ) : (
          <div className="text-3xl font-bold text-zinc-100">{value}</div>
        )}
      </CardContent>
    </Card>
  );
}