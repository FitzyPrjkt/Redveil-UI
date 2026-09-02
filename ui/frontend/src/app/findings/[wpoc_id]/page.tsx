"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { IconAlertTriangle, IconCircleCheck, IconHistory } from "@tabler/icons-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge as UiBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type FindingStatus = "discovered" | "suspected" | "validating" | "confirmed" | "likely" | "inconclusive" | "false_positive" | "reported";

interface FindingDetail {
  id: number;
  scan_id: number;
  wpoc_id: string;
  severity: Severity | string;
  confidence: string;
  status: FindingStatus | string;
  title: string;
  endpoint: string | null;
  check_id: string | null;
  created_at: string;
  fingerprint: string | null;
  finding_data?: {
    replay_recipe?: { method?: string; url?: string } | null;
    technical_explanation?: string;
    summary?: string;
    impact?: string;
    remediation?: string[];
    cwe?: string[];
    owasp?: string[];
  };
}

function severityClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
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
    case "confirmed":
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
    case "likely":
      return "bg-emerald-500/10 text-emerald-300 border-emerald-500/20";
    case "inconclusive":
      return "bg-yellow-500/10 text-yellow-300 border-yellow-500/20";
    case "false_positive":
      return "bg-zinc-700/40 text-zinc-400 border-zinc-600/30";
    default:
      return "bg-zinc-800 text-zinc-400 border-zinc-700";
  }
}

export default function FindingDetailPage({
  params,
}: {
  params: Promise<{ wpoc_id: string }>;
}) {
  const { wpoc_id } = use(params);
  const router = useRouter();
  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    apiGet<FindingDetail>(`/api/findings/${wpoc_id}`)
      .then((data) => {
        if (!cancelled) setFinding(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [wpoc_id]);

  if (loading) {
    return (
      <div className="space-y-6" data-testid="finding-detail-loading">
        <Skeleton className="h-12 w-1/3" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }
  if (error) {
    return (
      <div
        role="alert"
        className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
      >
        Failed to load finding: {error}
      </div>
    );
  }
  if (!finding) {
    return (
      <div
        role="alert"
        className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm text-yellow-300"
      >
        Finding <code className="font-mono">{wpoc_id}</code> not found.
      </div>
    );
  }

  const hasReplay = Boolean(
    finding.finding_data?.replay_recipe?.url,
  );

  return (
    <div className="space-y-8" data-testid="finding-detail">
      <header className="space-y-3">
        <div className="flex items-center gap-3">
          <h1
            className="font-serif text-3xl font-bold tracking-tight text-zinc-100"
            data-testid="finding-title"
          >
            {finding.title}
          </h1>
          <UiBadge
            variant="outline"
            className={cn("border", severityClass(finding.severity))}
          >
            {finding.severity}
          </UiBadge>
          <UiBadge
            variant="outline"
            className={cn("border", statusClass(finding.status))}
          >
            {finding.status}
          </UiBadge>
        </div>
        <div className="flex flex-wrap items-center gap-4 text-sm text-zinc-400">
          <span className="font-mono text-zinc-300">{finding.wpoc_id}</span>
          {finding.check_id ? (
            <span className="font-mono text-xs text-zinc-500">
              {finding.check_id}
            </span>
          ) : null}
          {finding.endpoint ? (
            <span className="font-mono text-xs text-zinc-500">
              {finding.endpoint}
            </span>
          ) : null}
        </div>
      </header>

      <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
        <CardHeader className="pb-3">
          <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">
            Actions
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          {hasReplay ? (
            <Button
              data-testid="replay-button"
              onClick={() => router.push(`/findings/${wpoc_id}/replay`)}
              className="gap-1.5"
            >
              <IconHistory size={14} aria-hidden="true" />
              Replay
            </Button>
          ) : (
            <div
              role="alert"
              data-testid="replay-unavailable"
              className="flex items-center gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-sm text-yellow-300"
            >
              <IconAlertTriangle size={14} aria-hidden="true" />
              <span>
                Replay not available — the check that produced this
                finding did not populate a replay_recipe.
              </span>
            </div>
          )}
        </CardContent>
      </Card>

      {finding.finding_data?.summary ? (
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
          <CardHeader className="pb-3">
            <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-relaxed text-zinc-200">
              {finding.finding_data.summary}
            </p>
          </CardContent>
        </Card>
      ) : null}

      {finding.finding_data?.technical_explanation ? (
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
          <CardHeader className="pb-3">
            <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Technical explanation
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-wrap font-mono text-xs text-zinc-300">
              {finding.finding_data.technical_explanation}
            </p>
          </CardContent>
        </Card>
      ) : null}

      {finding.finding_data?.remediation?.length ? (
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
          <CardHeader className="pb-3">
            <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Remediation
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="list-inside list-disc space-y-1 text-sm text-zinc-200">
              {finding.finding_data.remediation.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}

      <div className="flex items-center gap-2 text-xs text-zinc-500">
        <IconCircleCheck size={12} aria-hidden="true" />
        <Link href="/" className="hover:text-zinc-300">
          Back to Dashboard
        </Link>
      </div>
    </div>
  );
}