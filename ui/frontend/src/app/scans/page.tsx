"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { IconClock, IconLoader2 } from "@tabler/icons-react";
import { Card, CardContent } from "@/components/ui/card";
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
  max_destructive_level: string;
  allow_destructive: boolean;
  gate_mode: string;
}

interface Target {
  id: number;
  url: string;
  name: string | null;
}

type Filter = "all" | "running" | "completed" | "failed";

function statusClass(status: string): string {
  switch (status) {
    case "completed":
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
    case "running":
      return "bg-sky-500/15 text-sky-300 border-sky-500/30";
    case "failed":
      return "bg-red-500/15 text-red-300 border-red-500/30";
    case "pending":
      return "bg-zinc-700/40 text-zinc-300 border-zinc-600/30";
    default:
      return "bg-zinc-800 text-zinc-400 border-zinc-700";
  }
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

export default function ScanHistoryPage() {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>("all");

  useEffect(() => {
    Promise.all([
      apiGet<Scan[]>("/api/scans?limit=200"),
      apiGet<Target[]>("/api/targets"),
    ])
      .then(([s, t]) => {
        setScans(s);
        setTargets(t);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err));
      });
  }, []);

  const targetById = useMemo(() => {
    const map = new Map<number, Target>();
    targets?.forEach((t) => map.set(t.id, t));
    return map;
  }, [targets]);

  const totalScans = scans?.length ?? 0;
  const runningCount =
    scans?.filter((s) => s.status === "running").length ?? 0;

  const filtered = useMemo(() => {
    if (!scans) return [];
    return scans
      .filter((s) => filter === "all" || s.status === filter)
      .filter((s) => {
        if (!search.trim()) return true;
        const t = targetById.get(s.target_id);
        const hay = `${t?.url ?? ""} ${t?.name ?? ""}`.toLowerCase();
        return hay.includes(search.trim().toLowerCase());
      });
  }, [scans, filter, search, targetById]);

  return (
    <div className="space-y-8" data-testid="scan-history">
      <header className="space-y-2">
        <h1
          className="font-serif text-3xl font-bold tracking-tight text-zinc-100"
          data-testid="scan-history-title"
        >
          Scan history
        </h1>
      </header>

      {/* Stat tiles */}
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
          <CardContent className="space-y-1 p-5">
            <div className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Total scans
            </div>
            <div
              className="text-3xl font-bold text-zinc-100"
              data-testid="stat-total"
            >
              {scans === null ? "—" : totalScans}
            </div>
          </CardContent>
        </Card>
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
          <CardContent className="space-y-1 p-5">
            <div className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Running now
            </div>
            <div
              className={cn(
                "text-3xl font-bold",
                runningCount > 0 ? "text-emerald-400" : "text-zinc-500",
              )}
              data-testid="stat-running"
            >
              {scans === null ? "—" : runningCount}
            </div>
          </CardContent>
        </Card>
      </section>

      {/* Search + filter chips */}
      <div className="space-y-3">
        <input
          data-testid="scan-search"
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by target..."
          className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-4 text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-500 focus:outline-none"
        />
        <div role="tablist" className="flex flex-wrap gap-2">
          {(["all", "running", "completed", "failed"] as Filter[]).map(
            (f) => (
              <button
                key={f}
                role="tab"
                aria-selected={filter === f}
                data-testid={`scan-filter-${f}`}
                onClick={() => setFilter(f)}
                className={cn(
                  "rounded-full px-4 py-1.5 text-sm transition-colors",
                  filter === f
                    ? "bg-zinc-700 text-zinc-100"
                    : "bg-transparent text-zinc-400 hover:text-zinc-200",
                )}
              >
                {f === "all"
                  ? "All"
                  : f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ),
          )}
        </div>
      </div>

      {/* Error */}
      {error ? (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
        >
          Failed to load scans: {error}
        </div>
      ) : null}

      {/* Scan list */}
      {scans === null ? (
        <div className="space-y-3" data-testid="scan-history-loading">
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
        </div>
      ) : filtered.length === 0 ? (
        <div
          role="status"
          className="rounded-xl border border-zinc-800 bg-zinc-900 p-6 text-center text-sm text-zinc-500"
        >
          {scans.length === 0
            ? "No scans yet. Start one from Targets → New Scan."
            : "No scans match the current filter."}
        </div>
      ) : (
        <ul className="space-y-3" data-testid="scan-list">
          {filtered.map((s) => {
            const t = targetById.get(s.target_id);
            const isRunning = s.status === "running";
            return (
              <li key={s.id}>
                <Link
                  href={`/scans/${s.id}`}
                  data-testid="scan-card"
                  className="block"
                >
                  <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 transition-colors hover:border-zinc-700">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1 space-y-1.5">
                        <div className="font-mono text-base text-zinc-100">
                          {t?.url ?? `target #${s.target_id}`}
                        </div>
                        <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500">
                          <span className="font-mono">{s.profile}</span>
                          {s.error ? (
                            <>
                              <span>·</span>
                              <span className="text-red-400">
                                {s.error.length > 60
                                  ? `${s.error.slice(0, 60)}…`
                                  : s.error}
                              </span>
                            </>
                          ) : (
                            <>
                              <span>·</span>
                              <span>{s.total_requests} requests</span>
                            </>
                          )}
                          <span>·</span>
                          <span className="inline-flex items-center gap-1">
                            <IconClock
                              size={12}
                              className="text-zinc-500"
                              aria-hidden="true"
                            />
                            {timeAgo(s.started_at)}
                          </span>
                        </div>
                      </div>
                      <UiBadge
                        variant="outline"
                        data-testid="scan-status"
                        className={cn("shrink-0 border", statusClass(s.status))}
                      >
                        {isRunning ? (
                          <IconLoader2
                            size={10}
                            className="mr-1 animate-spin"
                            aria-hidden="true"
                          />
                        ) : null}
                        {s.status}
                      </UiBadge>
                    </div>
                  </Card>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}