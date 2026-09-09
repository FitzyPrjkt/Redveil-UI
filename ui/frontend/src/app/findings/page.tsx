"use client";

// Findings list (0.2.0 Phase 8) — cross-scan findings with the
// "Show suppressed (false positives)" toggle (spec §10).
//
// Default view hides false positives (backend does this via
// ?include_fp=false). Toggling persists per-browser in localStorage
// and refetches with ?include_fp=true; suppressed rows render muted
// with a "Suppressed" badge.

import { useEffect, useState } from "react";
import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { Badge as UiBadge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";
import IncludeFpToggle from "./components/IncludeFpToggle";

type Severity = "critical" | "high" | "medium" | "low" | "info";

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
  notes: string | null;
  annotated_at: string | null;
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
      return "bg-sky-500/15 text-sky-300 border-sky-500/30";
    default:
      return "bg-zinc-800 text-zinc-400 border-zinc-700";
  }
}

export default function FindingsListPage() {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [includeFp, setIncludeFp] = useState(false);

  useEffect(() => {
    let cancelled = false;
    apiGet<Finding[]>(`/api/findings?limit=500&include_fp=${includeFp}`)
      .then((rows) => {
        if (!cancelled) setFindings(rows);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [includeFp]);

  return (
    <div className="space-y-8" data-testid="findings-list-page">
      <header className="space-y-2">
        <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
          Findings
        </h1>
        <p className="text-sm text-zinc-400">
          Every finding across all scans, newest first.
        </p>
      </header>

      <IncludeFpToggle onChange={setIncludeFp} />

      {error ? (
        <div
          role="alert"
          data-testid="findings-error"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
        >
          Failed to load findings: {error}
        </div>
      ) : null}

      {findings === null && !error ? (
        <div className="space-y-3" data-testid="findings-loading">
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
        </div>
      ) : null}

      {findings !== null && findings.length === 0 && !error ? (
        <div
          role="status"
          data-testid="findings-empty"
          className="rounded-xl border border-zinc-800 bg-zinc-900 p-6 text-center text-sm text-zinc-500"
        >
          {includeFp
            ? "No findings recorded at all — including suppressed ones."
            : "No actionable findings. Toggle suppressed to include false positives."}
        </div>
      ) : null}

      {findings !== null && findings.length > 0 ? (
        <ul className="space-y-3" data-testid="findings-rows">
          {findings.map((f) => {
            const suppressed = f.status === "false_positive";
            return (
              <li key={f.id}>
                <Link href={`/findings/${f.wpoc_id}`} className="block">
                  <Card
                    className={cn(
                      "rounded-xl border bg-zinc-900 p-5 transition-colors hover:border-zinc-700",
                      suppressed
                        ? "border-zinc-800/60 opacity-60 hover:opacity-80"
                        : "border-zinc-800",
                    )}
                  >
                    <CardContent className="flex items-start justify-between gap-4 p-0">
                      <div className="min-w-0 flex-1 space-y-1.5">
                        <h3
                          className={cn(
                            "font-serif text-lg",
                            suppressed ? "text-zinc-400" : "text-zinc-100",
                          )}
                        >
                          {f.title}
                        </h3>
                        <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-zinc-500">
                          <span className="truncate">
                            {f.endpoint ?? "—"}
                          </span>
                          <span>·</span>
                          <span>scan #{f.scan_id}</span>
                        </div>
                      </div>
                      <div className="flex shrink-0 flex-wrap items-center gap-2">
                        {f.notes ? (
                          <UiBadge
                            variant="outline"
                            data-testid="finding-annotated-badge"
                            className="border border-sky-500/30 bg-sky-500/10 text-sky-300"
                          >
                            Annotated
                          </UiBadge>
                        ) : null}
                        {suppressed ? (
                          <UiBadge
                            variant="outline"
                            data-testid="finding-suppressed-badge"
                            className="border border-zinc-600/40 bg-zinc-800/60 text-zinc-400"
                          >
                            Suppressed
                          </UiBadge>
                        ) : null}
                        <UiBadge
                          variant="outline"
                          className={cn(
                            "border",
                            severityClass(f.severity),
                            suppressed && "opacity-70",
                          )}
                        >
                          {f.severity}
                        </UiBadge>
                      </div>
                    </CardContent>
                  </Card>
                </Link>
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}
