"use client";

import { use, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  IconAlertTriangle,
  IconCheck,
  IconCircleCheck,
  IconCircleX,
  IconClock,
  IconFlame,
  IconRefresh,
  IconWaveSine,
  IconX,
} from "@tabler/icons-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge as UiBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet, apiPost } from "@/lib/api";
import { cn } from "@/lib/utils";

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface FindingDetail {
  id: number;
  scan_id: number;
  wpoc_id: string;
  severity: Severity | string;
  confidence: string;
  status: string;
  title: string;
  endpoint: string | null;
  check_id: string | null;
  created_at: string;
  fingerprint: string | null;
}

interface ReplaySample {
  index: number;
  status_code: number;
  elapsed_ms: number;
  body_length: number;
  body_excerpt: string;
  error: string | null;
}

interface ReplayResult {
  wpoc_id: string;
  finding_title: string;
  target_url: string | null;
  method: string;
  samples: ReplaySample[];
  sample_count: number;
  success_count: number;
  total_duration_ms: number;
  consistent: boolean;
  status_variance: number;
  body_length_variance: number;
  body_content_match: boolean;
  timing_variance_ms: number;
  reliable: boolean;
  verdict: "Reproducible" | "Not verified" | "Flaky" | string;
  notes: string;
  executed_at: string;
}

function severityClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return "bg-red-500/15 text-red-300 border-red-500/30";
    case "medium":
      return "bg-yellow-500/15 text-yellow-300 border-yellow-500/30";
    case "low":
      return "bg-sky-500/15 text-sky-300 border-sky-500/30";
    default:
      return "bg-zinc-500/15 text-zinc-300 border-zinc-500/30";
  }
}

function statusClass(status: number): string {
  if (status >= 200 && status < 300)
    return "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
  if (status >= 300 && status < 400)
    return "bg-sky-500/15 text-sky-300 border-sky-500/30";
  if (status >= 400 && status < 500)
    return "bg-yellow-500/15 text-yellow-300 border-yellow-500/30";
  return "bg-red-500/15 text-red-300 border-red-500/30";
}

function verdictClass(verdict: string): {
  wrapper: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
} {
  switch (verdict) {
    case "Reproducible":
      return {
        wrapper:
          "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
        icon: IconCircleCheck,
      };
    case "Flaky":
      return {
        wrapper: "bg-orange-500/15 text-orange-300 border-orange-500/30",
        icon: IconWaveSine,
      };
    case "Not verified":
    default:
      return {
        wrapper: "bg-red-500/15 text-red-300 border-red-500/30",
        icon: IconCircleX,
      };
  }
}

function statusIconClass(status: number) {
  if (status >= 200 && status < 300) return "text-emerald-400";
  if (status >= 300 && status < 400) return "text-sky-400";
  return "text-red-400";
}

export default function ReplayPage({
  params,
}: PageProps<"/findings/[wpoc_id]/replay">) {
  const { wpoc_id } = use(params);

  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [result, setResult] = useState<ReplayResult | null>(null);
  const [loadingFinding, setLoadingFinding] = useState(true);
  const [replaying, setReplaying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load finding metadata on mount
  useEffect(() => {
    let cancelled = false;
    setLoadingFinding(true);
    setError(null);
    apiGet<FindingDetail>(`/api/findings/${encodeURIComponent(wpoc_id)}`)
      .then((f) => {
        if (!cancelled) setFinding(f);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoadingFinding(false);
      });
    return () => {
      cancelled = true;
    };
  }, [wpoc_id]);

  async function runReplay() {
    setReplaying(true);
    setError(null);
    try {
      const data = await apiPost<ReplayResult>(
        `/api/findings/${encodeURIComponent(wpoc_id)}/replay`,
        {},
      );
      setResult(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setReplaying(false);
    }
  }

  const verdictMeta = useMemo(
    () => (result ? verdictClass(result.verdict) : null),
    [result],
  );

  return (
    <div className="mx-auto max-w-4xl space-y-8">
      {/* Header */}
      <header className="space-y-3">
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <Link href="/" className="hover:text-zinc-300">
            Dashboard
          </Link>
          <span>/</span>
          <Link href="/scans" className="hover:text-zinc-300">
            Scans
          </Link>
          <span>/</span>
          <span className="font-mono text-zinc-300">{wpoc_id}</span>
        </div>

        {loadingFinding ? (
          <div className="space-y-2">
            <Skeleton className="h-8 w-2/3" />
            <Skeleton className="h-4 w-1/3" />
          </div>
        ) : finding ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
                Replay
              </h1>
              <UiBadge variant="outline" className="border-zinc-700 text-zinc-300">
                from <span className="ml-1 font-mono">{finding.wpoc_id}</span>
              </UiBadge>
              <UiBadge
                variant="outline"
                className={cn("border", severityClass(finding.severity))}
              >
                <IconFlame size={12} aria-hidden="true" />
                {finding.severity}
              </UiBadge>
              <UiBadge
                variant="outline"
                className="border-zinc-700 text-zinc-300"
              >
                {finding.status}
              </UiBadge>
            </div>
            <p className="font-sans text-base text-zinc-200">
              {finding.title}
            </p>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-zinc-500">
              {finding.check_id ? (
                <span>
                  check_id:{" "}
                  <span className="font-mono text-zinc-300">
                    {finding.check_id}
                  </span>
                </span>
              ) : null}
              {finding.endpoint ? (
                <span className="font-mono text-zinc-300">{finding.endpoint}</span>
              ) : null}
            </div>
          </div>
        ) : (
          <div className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm text-yellow-300">
            <IconAlertTriangle size={16} className="mt-0.5 shrink-0" />
            <span>Finding {wpoc_id} not found.</span>
          </div>
        )}
      </header>

      {/* Error from previous operations */}
      {error ? (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
        >
          <IconX size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </div>
      ) : null}

      {/* Verdict card (post-replay) */}
      {result && verdictMeta ? (
        <Card
          className={cn(
            "rounded-xl border bg-zinc-900",
            verdictMeta.wrapper,
          )}
          data-testid="replay-verdict"
        >
          <CardContent className="flex items-start gap-3 py-4">
            <verdictMeta.icon size={20} aria-hidden="true" />
            <div className="flex-1 space-y-1">
              <div className="text-base font-semibold">
                {result.verdict}
                {result.verdict === "Reproducible"
                  ? ` — consistent across ${result.sample_count} samples`
                  : null}
                {result.verdict === "Flaky"
                  ? ` — samples succeeded but disagreed`
                  : null}
                {result.verdict === "Not verified"
                  ? ` — recipe could not be reliably reproduced`
                  : null}
              </div>
              <div className="grid gap-3 text-xs sm:grid-cols-4">
                <div>
                  <div className="uppercase tracking-wider text-zinc-400">
                    Samples
                  </div>
                  <div className="font-mono text-sm text-zinc-100">
                    {result.sample_count}
                  </div>
                </div>
                <div>
                  <div className="uppercase tracking-wider text-zinc-400">
                    Success
                  </div>
                  <div className="font-mono text-sm text-zinc-100">
                    {result.success_count}/{result.sample_count}
                  </div>
                </div>
                <div>
                  <div className="uppercase tracking-wider text-zinc-400">
                    Timing variance
                  </div>
                  <div className="font-mono text-sm text-zinc-100">
                    {result.timing_variance_ms.toFixed(1)} ms
                  </div>
                </div>
                <div>
                  <div className="uppercase tracking-wider text-zinc-400">
                    Duration
                  </div>
                  <div className="font-mono text-sm text-zinc-100">
                    {result.total_duration_ms.toFixed(0)} ms
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* Recipe + replay button */}
      <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
        <CardHeader className="pb-3">
          <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">
            Recipe
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {result ? (
            <div className="space-y-2 font-mono text-sm">
              <div>
                <span className="text-sky-400">{result.method}</span>{" "}
                <span className="text-zinc-100">{result.target_url}</span>
              </div>
              <div className="text-xs text-zinc-500">
                Authorization: <span className="text-zinc-400">[REDACTED]</span>
              </div>
            </div>
          ) : finding ? (
            <div className="space-y-2 font-mono text-sm text-zinc-400">
              {finding.endpoint ? (
                <div>{finding.endpoint}</div>
              ) : (
                <div>Recipe will be loaded on first replay.</div>
              )}
            </div>
          ) : (
            <Skeleton className="h-10 w-full" />
          )}

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <Button
              data-testid="replay-run"
              onClick={runReplay}
              disabled={replaying || loadingFinding || !finding}
              className="h-11 gap-2 px-6 text-sm font-semibold"
            >
              {replaying ? (
                <>
                  <IconRefresh
                    size={16}
                    className="animate-spin"
                    aria-hidden="true"
                  />
                  Replaying…
                </>
              ) : (
                <>
                  <IconRefresh size={16} aria-hidden="true" />
                  Replay × 3
                </>
              )}
            </Button>
            <Button
              variant="outline"
              disabled
              className="h-11 px-6 text-sm"
              title="Edit request — coming in v2"
            >
              Edit request
            </Button>
            {result ? (
              <span className="ml-auto flex items-center gap-1 text-xs text-zinc-500">
                <IconClock size={12} aria-hidden="true" />
                executed {new Date(result.executed_at).toLocaleTimeString()}
              </span>
            ) : null}
          </div>
        </CardContent>
      </Card>

      {/* Samples table */}
      <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
        <CardHeader className="pb-3">
          <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">
            Samples
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!result ? (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950 px-4 py-3"
                >
                  <Skeleton className="h-4 w-24" />
                  <Skeleton className="h-4 w-16" />
                </div>
              ))}
              <p className="pt-2 text-xs text-zinc-500">
                Click <span className="font-mono">Replay × 3</span> to send the
                recipe 3 times and compare responses.
              </p>
            </div>
          ) : result.samples.length === 0 ? (
            <div className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm text-yellow-300">
              <IconAlertTriangle size={16} className="mt-0.5 shrink-0" />
              <span>
                All samples failed. Check that the target is reachable and that
                the recipe URL/host are still valid.
              </span>
            </div>
          ) : (
            <ul className="divide-y divide-zinc-800">
              {result.samples.map((s) => (
                <li
                  key={s.index}
                  data-testid="replay-sample"
                  className="grid grid-cols-12 items-center gap-4 px-4 py-3"
                >
                  <span className="col-span-4 font-mono text-sm text-zinc-100">
                    Sample {s.index}
                  </span>
                  <span
                    className={cn(
                      "col-span-2 inline-flex h-6 w-fit items-center justify-center rounded-md border px-2 font-mono text-xs",
                      statusClass(s.status_code),
                    )}
                  >
                    <span className={statusIconClass(s.status_code)}>
                      {s.status_code}
                    </span>
                  </span>
                  <span className="col-span-2 font-mono text-xs text-zinc-300">
                    {s.body_length} B
                  </span>
                  <span className="col-span-2 font-mono text-xs text-emerald-300">
                    {s.elapsed_ms.toFixed(0)} ms
                  </span>
                  <span className="col-span-2 text-right text-xs text-zinc-500">
                    {s.error ? (
                      <span className="font-mono text-red-400">{s.error}</span>
                    ) : (
                      "ok"
                    )}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Notes (optional) */}
      {result?.notes ? (
        <p className="font-mono text-xs text-zinc-500">{result.notes}</p>
      ) : null}
    </div>
  );
}