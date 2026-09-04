"use client";

import { use, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  IconAlertTriangle,
  IconCheck,
  IconCircleCheck,
  IconExternalLink,
  IconLoader2,
} from "@tabler/icons-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge as UiBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type ScanStatus = "pending" | "running" | "completed" | "failed";
type Tab = "findings" | "sitemap" | "evidence";

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

interface Finding {
  id: number;
  scan_id: number;
  wpoc_id: string;
  severity: string;
  confidence: string;
  status: string;
  title: string;
  endpoint: string | null;
  check_id: string | null;
  created_at: string;
}

function severityClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-red-600/15 text-red-300 border-red-600/30";
    case "high":
      return "bg-red-500/15 text-red-300 border-red-500/30";
    case "medium":
      return "bg-yellow-500/15 text-yellow-300 border-yellow-500/30";
    case "low":
      return "bg-zinc-700/40 text-zinc-300 border-zinc-600/30";
    default:
      return "bg-zinc-800 text-zinc-400 border-zinc-700";
  }
}

function statusClass(status: string): string {
  switch (status.toLowerCase()) {
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

export default function ScanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const scanId = Number(id);
  const router = useRouter();

  const [scan, setScan] = useState<Scan | null>(null);
  const [target, setTarget] = useState<Target | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("findings");

  useEffect(() => {
    if (Number.isNaN(scanId)) {
      setError("Invalid scan id");
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      apiGet<Scan>(`/api/scans/${scanId}`).catch(() => null),
      apiGet<Finding[]>(`/api/scans/${scanId}/findings`).catch(() => []),
    ])
      .then(([s, f]) => {
        if (cancelled) return;
        if (!s) {
          setError(`Scan #${scanId} not found`);
          return;
        }
        setScan(s);
        setFindings(f);
        return apiGet<Target>(`/api/targets/${s.target_id}`)
          .then((t) => {
            if (!cancelled) setTarget(t);
          });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  // Severity counts.
  const severityCounts = useMemo(() => {
    const counts = { high: 0, medium: 0, low: 0 };
    findings?.forEach((f) => {
      const s = f.severity.toLowerCase();
      if (s === "high" || s === "critical") counts.high += 1;
      else if (s === "medium") counts.medium += 1;
      else if (s === "low") counts.low += 1;
    });
    return counts;
  }, [findings]);

  // Mockup shows 11/17 checks progress; use findings count as a proxy.
  const totalChecks = findings?.length ?? 0;
  const progressLabel = `${totalChecks}/17`;
  const progressPct = totalChecks > 0 ? Math.min(100, (totalChecks / 17) * 100) : 0;

  if (loading) {
    return (
      <div className="space-y-6" data-testid="scan-detail-loading">
        <Skeleton className="h-12 w-1/2" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }
  if (error || !scan) {
    return (
      <div
        role="alert"
        className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
      >
        {error ?? `Scan #${scanId} not found.`}
      </div>
    );
  }

  const isRunning = scan.status === "running";
  const isFailed = scan.status === "failed";

  return (
    <div className="space-y-8" data-testid="scan-detail">
      {/* Header */}
      <header className="space-y-2">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 space-y-1">
            <h1
              className="truncate font-mono text-2xl font-bold tracking-tight text-zinc-100"
              data-testid="scan-target"
            >
              {target?.url ?? `target #${scan.target_id}`}
            </h1>
            <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500">
              <span className="font-mono">{scan.profile}</span>
              <span>·</span>
              <span>scan #{scan.id}</span>
              {scan.total_requests > 0 ? (
                <>
                  <span>·</span>
                  <span>{scan.total_requests} requests</span>
                </>
              ) : null}
            </div>
          </div>
          <UiBadge
            variant="outline"
            data-testid="scan-status"
            className={cn("border", statusClass(scan.status))}
          >
            {isRunning ? (
              <IconLoader2
                size={10}
                className="mr-1 animate-spin"
                aria-hidden="true"
              />
            ) : null}
            {scan.status}
          </UiBadge>
        </div>
        {isFailed && scan.error ? (
          <div
            role="alert"
            data-testid="scan-error"
            className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
          >
            <IconAlertTriangle
              size={16}
              className="mt-0.5 shrink-0"
              aria-hidden="true"
            />
            <span>
              <strong className="text-red-200">Scan failed.</strong> {scan.error}
            </span>
          </div>
        ) : null}
      </header>

      {/* Progress */}
      <section
        data-testid="scan-progress"
        className="space-y-1.5"
      >
        <div className="flex items-center justify-between text-sm">
          <span className="text-zinc-400">check.progress</span>
          <span className="font-mono text-zinc-300">{progressLabel}</span>
        </div>
        <div
          role="progressbar"
          aria-valuenow={Math.round(progressPct)}
          aria-valuemin={0}
          aria-valuemax={100}
          className="h-2 overflow-hidden rounded-full bg-zinc-800"
        >
          <div
            className="h-full bg-sky-500 transition-all"
            style={{ width: `${progressPct}%` }}
          />
        </div>
      </section>

      {/* Severity tiles */}
      <section
        aria-label="Severity breakdown"
        className="grid gap-4 sm:grid-cols-3"
      >
        <SeverityTile
          label="high"
          count={severityCounts.high}
          tone="red"
          dataTestid="severity-high"
        />
        <SeverityTile
          label="medium"
          count={severityCounts.medium}
          tone="yellow"
          dataTestid="severity-medium"
        />
        <SeverityTile
          label="low"
          count={severityCounts.low}
          tone="zinc"
          dataTestid="severity-low"
        />
      </section>

      {/* Tabs */}
      <div role="tablist" className="flex gap-6 border-b border-zinc-800">
        {(
          [
            { id: "findings" as Tab, label: "Findings" },
            {
              id: "sitemap" as Tab,
              label: "Site map",
              href: target ? `/targets/${target.id}` : null,
            },
            {
              id: "evidence" as Tab,
              label: "Evidence",
              href: `/scans/${scanId}/evidence`,
            },
          ] as { id: Tab; label: string; href: string | null }[]
        ).map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            data-testid={`tab-${t.id}`}
            onClick={() => {
              setTab(t.id);
              if (t.href) router.push(t.href);
            }}
            className={cn(
              "-mb-px border-b-2 px-1 py-3 text-sm transition-colors",
              tab === t.id
                ? "border-zinc-200 text-zinc-100"
                : "border-transparent text-zinc-400 hover:text-zinc-200",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Findings list */}
      {tab === "findings" ? (
        findings === null ? (
          <Skeleton className="h-32 w-full" />
        ) : findings.length === 0 ? (
          <div
            role="status"
            data-testid="findings-empty"
            className="flex flex-col items-center gap-2 rounded-xl border border-zinc-800 bg-zinc-900 p-8 text-center"
          >
            <IconCircleCheck
              size={32}
              className="text-emerald-400"
              aria-hidden="true"
            />
            <p className="text-sm text-zinc-300">
              {isRunning
                ? "No findings yet — scan still running."
                : "No findings. The target passed all registered checks."}
            </p>
          </div>
        ) : (
          <ul
            data-testid="findings-list"
            className="space-y-3"
          >
            {findings.map((f) => (
              <li key={f.id}>
                <Link
                  href={`/findings/${f.wpoc_id}`}
                  data-testid="finding-card"
                  className="block"
                >
                  <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 transition-colors hover:border-zinc-700">
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1 space-y-1.5">
                        <h3 className="font-serif text-lg text-zinc-100">
                          {f.title}
                        </h3>
                        <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-zinc-500">
                          <span className="truncate">
                            {f.endpoint ?? "—"}
                          </span>
                        </div>
                      </div>
                      <UiBadge
                        variant="outline"
                        className={cn("shrink-0 border", severityClass(f.severity))}
                      >
                        {f.severity}
                      </UiBadge>
                    </div>
                  </Card>
                </Link>
              </li>
            ))}
          </ul>
        )
      ) : null}
    </div>
  );
}

function SeverityTile({
  label,
  count,
  tone,
  dataTestid,
}: {
  label: string;
  count: number;
  tone: "red" | "yellow" | "zinc";
  dataTestid: string;
}) {
  const toneClass =
    tone === "red"
      ? "bg-red-500/10 border-red-500/20"
      : tone === "yellow"
      ? "bg-yellow-500/10 border-yellow-500/20"
      : "bg-sky-500/10 border-sky-500/20";
  const textClass =
    tone === "red"
      ? "text-red-300"
      : tone === "yellow"
      ? "text-yellow-300"
      : "text-sky-300";
  return (
    <Card
      data-testid={dataTestid}
      className={cn("rounded-xl border p-5", toneClass)}
    >
      <CardContent className="space-y-1 p-0">
        <div className={cn("text-4xl font-bold", textClass)}>{count}</div>
        <div className="text-xs font-medium uppercase tracking-wider text-zinc-400">
          {label}
        </div>
      </CardContent>
    </Card>
  );
}