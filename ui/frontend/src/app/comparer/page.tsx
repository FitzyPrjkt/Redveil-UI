"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import {
  IconAlertTriangle,
  IconArrowsRightLeft,
  IconCircleDot,
} from "@tabler/icons-react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Evidence {
  finding_id: string;
  evidence_id: string;
  title: string;
  severity: string;
  endpoint: string | null;
  method: string | null;
  status_code: number | null;
  timing_ms: number | null;
  length: number | null;
  body_excerpt: string | null;
  input_used: string | null;
}

// Fields the comparer shows side-by-side. Labels use monospace-friendly
// strings so the diff grid lines up with the mockup.
const DIFF_FIELDS: {
  key: keyof Pick<
    Evidence,
    "status_code" | "timing_ms" | "length" | "body_excerpt"
  >;
  label: string;
}[] = [
  { key: "status_code", label: "status_code" },
  { key: "timing_ms", label: "timing_ms" },
  { key: "length", label: "content-length" },
  { key: "body_excerpt", label: "body_excerpt" },
];

function formatValue(key: string, val: unknown): string {
  if (val === null || val === undefined || val === "") return "—";
  if (key === "timing_ms" && typeof val === "number") {
    return `${val}ms`;
  }
  if (key === "length" && typeof val === "number") {
    return String(val);
  }
  return String(val);
}

function severityTone(severity: string): string {
  if (severity === "high" || severity === "critical") {
    return "bg-red-500/10 text-red-300 border-red-500/30";
  }
  if (severity === "medium") {
    return "bg-yellow-500/10 text-yellow-300 border-yellow-500/30";
  }
  if (severity === "low") {
    return "bg-sky-500/10 text-sky-300 border-sky-500/30";
  }
  return "bg-zinc-500/10 text-zinc-300 border-zinc-500/30";
}

function ComparerInner() {
  const params = useSearchParams();
  const initialScanId = params.get("scan_id") ?? "1";

  const [scanId, setScanId] = useState(initialScanId);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [leftId, setLeftId] = useState<string>("");
  const [rightId, setRightId] = useState<string>("");

  // Fetch when scanId changes.
  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const data = await apiGet<Evidence[]>(
          `/api/scans/${scanId}/evidence`,
        );
        if (cancelled) return;
        setEvidence(data);
        // Default to first two distinct entries so the diff has something
        // to show immediately.
        if (data.length >= 2) {
          setLeftId((prev) =>
            prev && data.some((d) => d.evidence_id === prev)
              ? prev
              : data[0].evidence_id,
          );
          setRightId((prev) =>
            prev && data.some((d) => d.evidence_id === prev)
              ? prev
              : data[1].evidence_id,
          );
        } else if (data.length === 1) {
          setLeftId((prev) =>
            prev && data.some((d) => d.evidence_id === prev)
              ? prev
              : data[0].evidence_id,
          );
          setRightId((prev) =>
            prev && data.some((d) => d.evidence_id === prev)
              ? prev
              : data[0].evidence_id,
          );
        } else {
          setLeftId("");
          setRightId("");
        }
      } catch (err: unknown) {
        if (cancelled) return;
        setEvidence([]);
        setLeftId("");
        setRightId("");
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    if (scanId) load();
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  const left = useMemo(
    () => evidence.find((e) => e.evidence_id === leftId) ?? null,
    [evidence, leftId],
  );
  const right = useMemo(
    () => evidence.find((e) => e.evidence_id === rightId) ?? null,
    [evidence, rightId],
  );

  const diffSummary = useMemo(() => {
    if (!left || !right) return null;
    const diffs: { field: string; leftVal: unknown; rightVal: unknown }[] = [];
    for (const f of DIFF_FIELDS) {
      if (left[f.key] !== right[f.key]) {
        diffs.push({
          field: f.label,
          leftVal: left[f.key],
          rightVal: right[f.key],
        });
      }
    }
    const timingDelta =
      left.timing_ms !== null &&
      right.timing_ms !== null &&
      left.timing_ms !== right.timing_ms
        ? right.timing_ms - left.timing_ms
        : null;
    return { diffs, timingDelta };
  }, [left, right]);

  function swap() {
    setLeftId(rightId);
    setRightId(leftId);
  }

  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-2">
          <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
            Comparer
          </h1>
          <p className="text-sm text-zinc-400">
            Diff two evidence records side by side. Useful for spotting
            timing or status deltas between a baseline request and a probe.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label
            htmlFor="scan-id"
            className="text-xs uppercase tracking-wider text-zinc-500"
          >
            Scan
          </label>
          <Input
            id="scan-id"
            data-testid="comparer-scan-id"
            type="number"
            min={1}
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            className="w-24 border-zinc-700 bg-zinc-950 text-zinc-100"
          />
          <Button
            variant="ghost"
            size="sm"
            onClick={swap}
            disabled={!left || !right}
            data-testid="comparer-swap"
            className="gap-1 text-xs"
          >
            <IconArrowsRightLeft size={14} aria-hidden="true" />
            Swap
          </Button>
        </div>
      </header>

      {error ? (
        <div
          role="alert"
          data-testid="comparer-error"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
        >
          {error}
        </div>
      ) : null}

      {/* Pickers */}
      <div className="grid gap-4 lg:grid-cols-2">
        <EvidencePicker
          label="Baseline"
          side="left"
          value={leftId}
          onChange={setLeftId}
          evidence={evidence}
          loading={loading}
        />
        <EvidencePicker
          label="Probe"
          side="right"
          value={rightId}
          onChange={setRightId}
          evidence={evidence}
          loading={loading}
        />
      </div>

      {/* Side-by-side diff */}
      {left && right ? (
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <div className="space-y-4">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">
              Diff
            </h2>

            <div className="overflow-x-auto rounded-lg border border-zinc-800">
              <table
                data-testid="comparer-diff"
                className="w-full border-collapse font-mono text-sm"
              >
                <thead className="bg-zinc-950 text-xs uppercase tracking-wider text-zinc-500">
                  <tr>
                    <th className="px-3 py-2 text-left">Field</th>
                    <th className="px-3 py-2 text-left">Baseline</th>
                    <th className="px-3 py-2 text-left">Probe</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {DIFF_FIELDS.map((f) => {
                    const differs = left[f.key] !== right[f.key];
                    return (
                      <tr key={f.key}>
                        <td className="px-3 py-2 text-zinc-500">{f.label}</td>
                        <td
                          data-testid={`diff-left-${f.key}`}
                          className={cn(
                            "px-3 py-2 text-zinc-200",
                            differs && "bg-yellow-500/10 text-yellow-200",
                          )}
                        >
                          {formatValue(f.key, left[f.key])}
                        </td>
                        <td
                          data-testid={`diff-right-${f.key}`}
                          className={cn(
                            "px-3 py-2 text-zinc-200",
                            differs && "bg-yellow-500/10 text-yellow-200",
                          )}
                        >
                          {formatValue(f.key, right[f.key])}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {diffSummary ? (
              <div
                role="status"
                data-testid="comparer-summary"
                className={cn(
                  "flex items-start gap-2 rounded-lg border p-3 text-sm",
                  diffSummary.diffs.length === 0
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                    : "border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
                )}
              >
                {diffSummary.diffs.length === 0 ? (
                  <IconCircleDot
                    size={18}
                    className="mt-0.5 shrink-0"
                    aria-hidden="true"
                  />
                ) : (
                  <IconAlertTriangle
                    size={18}
                    className="mt-0.5 shrink-0"
                    aria-hidden="true"
                  />
                )}
                <span>
                  {diffSummary.diffs.length === 0
                    ? "All fields identical."
                    : `Diff: ${diffSummary.diffs.length} field(s) differ${
                        diffSummary.timingDelta !== null
                          ? ` — timing Δ ${diffSummary.timingDelta > 0 ? "+" : ""}${diffSummary.timingDelta}ms`
                          : ""
                      }.`}
                </span>
              </div>
            ) : null}
          </div>
        </Card>
      ) : evidence.length === 0 && !loading ? (
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-6 text-center text-sm text-zinc-500">
          No evidence records available for this scan.
        </Card>
      ) : null}
    </div>
  );
}

function EvidencePicker({
  label,
  side,
  value,
  onChange,
  evidence,
  loading,
}: {
  label: string;
  side: "left" | "right";
  value: string;
  onChange: (v: string) => void;
  evidence: Evidence[];
  loading: boolean;
}) {
  return (
    <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-zinc-500">
            {label}
          </span>
          {loading ? (
            <span className="text-xs text-zinc-500">loading…</span>
          ) : null}
        </div>
        <select
          data-testid={`comparer-${side}-select`}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
        >
          {evidence.length === 0 ? (
            <option value="">— no evidence —</option>
          ) : (
            evidence.map((e) => (
              <option key={e.evidence_id} value={e.evidence_id}>
                {e.evidence_id} · {e.title}
              </option>
            ))
          )}
        </select>
        <EvidenceCard evidence={evidence.find((e) => e.evidence_id === value) ?? null} />
      </div>
    </Card>
  );
}

function EvidenceCard({ evidence }: { evidence: Evidence | null }) {
  if (!evidence) return null;
  return (
    <div
      data-testid="comparer-card"
      className="space-y-2 rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-xs"
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-zinc-100">{evidence.title}</span>
        <span
          className={cn(
            "shrink-0 rounded-md border px-2 py-0.5",
            severityTone(evidence.severity),
          )}
        >
          {evidence.severity}
        </span>
      </div>
      <div className="text-zinc-500">{evidence.endpoint ?? "—"}</div>
      <div className="grid grid-cols-2 gap-1 pt-1">
        <span className="text-zinc-500">status</span>
        <span className="text-zinc-200">
          {evidence.status_code ?? "—"}
        </span>
        <span className="text-zinc-500">timing</span>
        <span className="text-zinc-200">
          {evidence.timing_ms !== null ? `${evidence.timing_ms}ms` : "—"}
        </span>
        <span className="text-zinc-500">length</span>
        <span className="text-zinc-200">{evidence.length ?? "—"}</span>
        <span className="text-zinc-500">input</span>
        <span className="truncate text-zinc-200">
          {evidence.input_used ?? "—"}
        </span>
      </div>
    </div>
  );
}

export default function ComparerPage() {
  return (
    <Suspense
      fallback={
        <div className="p-6 text-sm text-zinc-500">Loading comparer…</div>
      }
    >
      <ComparerInner />
    </Suspense>
  );
}