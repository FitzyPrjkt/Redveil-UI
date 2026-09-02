"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import {
  IconChevronDown,
  IconChevronRight,
  IconClock,
  IconFilter,
  IconSearch,
} from "@tabler/icons-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";

// --- Types --------------------------------------------------------------

interface EvidenceRow {
  finding_id: string;
  evidence_id: string;
  title: string;
  severity: string;
  endpoint: string | null;
  method: string | null;
  status_code: number | null;
  timing_ms: number | null;
  baseline_timing_ms: number | null;
  body_excerpt: string | null;
  input_used: string | null;
  check_id: string | null;
  timestamp: string | null;
}

interface Scan {
  id: number;
  target_id: number;
  status: string;
}

interface Target {
  id: number;
  url: string;
}

// --- Helpers ------------------------------------------------------------

function statusBadgeClass(code: number | null): string {
  if (code === null) return "bg-zinc-800 text-zinc-400 border-zinc-700";
  if (code >= 200 && code < 300) return "bg-emerald-500/15 text-emerald-300 border-emerald-500/20";
  if (code >= 300 && code < 400) return "bg-sky-500/15 text-sky-300 border-sky-500/20";
  if (code >= 400 && code < 500) return "bg-yellow-500/15 text-yellow-300 border-yellow-500/20";
  if (code >= 500 && code < 600) return "bg-red-500/15 text-red-300 border-red-500/20";
  return "bg-zinc-800 text-zinc-400 border-zinc-700";
}

function methodColor(method: string | null): string {
  switch ((method || "GET").toUpperCase()) {
    case "GET":
      return "text-sky-400";
    case "POST":
      return "text-emerald-400";
    case "PUT":
      return "text-yellow-400";
    case "PATCH":
      return "text-orange-400";
    case "DELETE":
      return "text-red-400";
    default:
      return "text-zinc-400";
  }
}

function formatTime(iso: string | null): string {
  if (!iso) return "—";
  // Trim microseconds for readability — the orchestrator writes
  // e.g. "2026-09-02T14:22:08.123456+00:00". We want HH:MM:SS.
  const t = iso.split("T")[1] ?? "";
  const hmmss = t.split(".")[0] ?? t;
  return hmmss || "—";
}

function truncateEndpoint(ep: string | null, max = 60): string {
  if (!ep) return "(no endpoint)";
  return ep.length > max ? ep.slice(0, max - 3) + "..." : ep;
}

// --- Filters ------------------------------------------------------------

const METHODS: { value: string | null; label: string }[] = [
  { value: null, label: "All" },
  { value: "GET", label: "GET" },
  { value: "POST", label: "POST" },
  { value: "PUT", label: "PUT" },
  { value: "DELETE", label: "DELETE" },
  { value: "PATCH", label: "PATCH" },
];

const STATUS_RANGES: { value: string | null; label: string; min: number | null; max: number | null }[] =
  [
    { value: null, label: "All", min: null, max: null },
    { value: "2xx", label: "2xx", min: 200, max: 299 },
    { value: "3xx", label: "3xx", min: 300, max: 399 },
    { value: "4xx", label: "4xx", min: 400, max: 499 },
    { value: "5xx", label: "5xx", min: 500, max: 599 },
  ];

// --- Row ---------------------------------------------------------------

function EvidenceRowItem({
  row,
  expanded,
  onToggle,
}: {
  row: EvidenceRow;
  expanded: boolean;
  onToggle: () => void;
}) {
  const isTimingBased = row.check_id === "sqli-time-based" || row.check_id === "command-injection";
  return (
    <Card
      className={cn(
        "rounded-xl border border-zinc-800 bg-zinc-900 transition-colors",
        expanded && "ring-1 ring-zinc-700",
      )}
      data-testid="evidence-row"
    >
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center gap-4 px-5 py-4 text-left hover:bg-zinc-900/60"
        aria-expanded={expanded}
      >
        {expanded ? (
          <IconChevronDown
            size={14}
            className="shrink-0 text-zinc-500"
            aria-hidden="true"
          />
        ) : (
          <IconChevronRight
            size={14}
            className="shrink-0 text-zinc-500"
            aria-hidden="true"
          />
        )}
        <span
          className={cn(
            "shrink-0 font-mono text-xs font-semibold tracking-wide",
            methodColor(row.method),
          )}
        >
          {(row.method || "GET").toUpperCase()}
        </span>
        <code className="flex-1 truncate font-mono text-sm text-zinc-200">
          {truncateEndpoint(row.endpoint)}
        </code>
        {row.status_code !== null ? (
          <Badge
            variant="outline"
            className={cn(
              "min-w-12 justify-center border font-mono",
              statusBadgeClass(row.status_code),
            )}
          >
            {row.status_code}
          </Badge>
        ) : (
          <Badge
            variant="outline"
            className="border border-zinc-800 font-mono text-zinc-500"
          >
            —
          </Badge>
        )}
      </button>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 pb-4 text-xs text-zinc-500">
        {row.check_id ? (
          <span className="flex items-center gap-1">
            <IconFilter size={12} aria-hidden="true" />
            <code className="font-mono text-zinc-400">{row.check_id}</code>
          </span>
        ) : null}
        {isTimingBased && row.baseline_timing_ms !== null && row.timing_ms !== null ? (
          <span className="flex items-center gap-1">
            <IconClock size={12} aria-hidden="true" />
            baseline {Math.round(row.baseline_timing_ms)}ms →{" "}
            <span className="font-mono text-zinc-300">
              {Math.round(row.timing_ms)}ms
            </span>
          </span>
        ) : row.timing_ms !== null ? (
          <span className="flex items-center gap-1">
            <IconClock size={12} aria-hidden="true" />
            <span className="font-mono text-zinc-300">
              {Math.round(row.timing_ms)}ms
            </span>
          </span>
        ) : null}
        <span className="ml-auto flex items-center gap-1">
          <code className="font-mono text-zinc-500">{row.evidence_id}</code>
          <span className="text-zinc-600">·</span>
          <span className="font-mono text-zinc-400">{formatTime(row.timestamp)}</span>
        </span>
      </div>

      {expanded ? (
        <div className="space-y-3 border-t border-zinc-800 px-5 py-4">
          {row.input_used ? (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                Input used
              </h4>
              <pre className="mt-1 overflow-x-auto whitespace-pre-wrap rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-xs text-zinc-300">
                {row.input_used}
              </pre>
            </div>
          ) : null}
          {row.body_excerpt ? (
            <div>
              <h4 className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                Response body
              </h4>
              <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap rounded-md border border-zinc-800 bg-zinc-950 p-3 font-mono text-xs text-zinc-300">
                {row.body_excerpt}
              </pre>
            </div>
          ) : null}
          {!row.input_used && !row.body_excerpt ? (
            <p className="text-xs text-zinc-500">
              No request/response payload recorded for this evidence.
            </p>
          ) : null}
          <div className="flex flex-wrap gap-3 text-xs text-zinc-500">
            <span>
              finding:{" "}
              <code className="font-mono text-zinc-400">{row.finding_id}</code>
            </span>
            {row.severity ? (
              <span>
                severity:{" "}
                <code className="font-mono text-zinc-400">{row.severity}</code>
              </span>
            ) : null}
          </div>
        </div>
      ) : null}
    </Card>
  );
}

// --- Page --------------------------------------------------------------

export default function EvidenceLogPage() {
  const params = useParams<{ id: string }>();
  const scanId = params?.id;

  const [scan, setScan] = useState<Scan | null>(null);
  const [target, setTarget] = useState<Target | null>(null);
  const [rows, setRows] = useState<EvidenceRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [methodFilter, setMethodFilter] = useState<string | null>(null);
  const [statusRange, setStatusRange] = useState<string | null>(null);
  const [checkIdQuery, setCheckIdQuery] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Build the URL with filters applied.
  const apiUrl = useMemo(() => {
    if (!scanId) return null;
    const params = new URLSearchParams();
    if (methodFilter) params.set("method", methodFilter);
    if (statusRange) {
      const range = STATUS_RANGES.find((r) => r.value === statusRange);
      if (range?.min !== null && range.min !== undefined) params.set("status_min", String(range.min));
      if (range?.max !== null && range.max !== undefined) params.set("status_max", String(range.max));
    }
    if (checkIdQuery.trim()) params.set("check_id", checkIdQuery.trim());
    const qs = params.toString();
    return `/api/scans/${scanId}/evidence${qs ? `?${qs}` : ""}`;
  }, [scanId, methodFilter, statusRange, checkIdQuery]);

  // Load scan + target context (just once).
  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    (async () => {
      try {
        const s = await apiGet<Scan>(`/api/scans/${scanId}`);
        if (cancelled) return;
        setScan(s);
        const t = await apiGet<Target>(`/api/targets/${s.target_id}`);
        if (cancelled) return;
        setTarget(t);
      } catch (err: unknown) {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  // Load evidence (refetches whenever filters change).
  useEffect(() => {
    if (!apiUrl) return;
    let cancelled = false;
    setLoading(true);
    apiGet<EvidenceRow[]>(apiUrl)
      .then((data) => {
        if (cancelled) return;
        setRows(data);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : String(err);
        setError(message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [apiUrl]);

  return (
    <div className="space-y-8" data-testid="evidence-log-page">
      <header className="space-y-2">
        <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
          Evidence log
        </h1>
        {target ? (
          <p className="font-mono text-sm text-zinc-400">
            scan <span className="text-zinc-300">#{scanId}</span> ·{" "}
            <span className="text-zinc-300">{target.url}</span>
          </p>
        ) : (
          <p className="font-mono text-sm text-zinc-500">scan #{scanId}</p>
        )}
        <p className="text-sm text-zinc-500">
          Chronological HTTP request/response observations recorded during the
          scan. Click any row to expand request/response details.
        </p>
      </header>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wider text-zinc-500">
            Method
          </span>
          <div className="flex gap-1">
            {METHODS.map((m) => {
              const selected = methodFilter === m.value;
              return (
                <Button
                  key={m.label}
                  size="sm"
                  variant={selected ? "default" : "outline"}
                  aria-pressed={selected}
                  onClick={() => setMethodFilter(m.value)}
                >
                  {m.label}
                </Button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wider text-zinc-500">
            Status
          </span>
          <div className="flex gap-1">
            {STATUS_RANGES.map((s) => {
              const selected = statusRange === s.value;
              return (
                <Button
                  key={s.label}
                  size="sm"
                  variant={selected ? "default" : "outline"}
                  aria-pressed={selected}
                  onClick={() => setStatusRange(s.value)}
                >
                  {s.label}
                </Button>
              );
            })}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wider text-zinc-500">
            Check
          </span>
          <div className="relative">
            <IconSearch
              size={14}
              className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-zinc-500"
              aria-hidden="true"
            />
            <Input
              type="text"
              value={checkIdQuery}
              onChange={(e) => setCheckIdQuery(e.target.value)}
              placeholder="check_id"
              className="w-44 border-zinc-700 bg-zinc-950 pl-7 text-xs text-zinc-100 placeholder:text-zinc-500"
            />
          </div>
        </div>

        <div className="ml-auto text-xs text-zinc-500">
          {loading ? "loading…" : `${rows.length} row${rows.length === 1 ? "" : "s"}`}
        </div>
      </div>

      {error ? (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
        >
          Failed to load evidence: {error}
        </div>
      ) : null}

      {/* Evidence rows */}
      <section className="space-y-2">
        {loading && rows.length === 0 ? (
          <Skeleton className="h-20 w-full rounded-xl bg-zinc-900" />
        ) : rows.length === 0 ? (
          <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-8 text-center text-sm text-zinc-500">
            No evidence matches the current filters.
          </Card>
        ) : (
          rows.map((row) => (
            <EvidenceRowItem
              key={row.evidence_id}
              row={row}
              expanded={expandedId === row.evidence_id}
              onToggle={() =>
                setExpandedId((cur) => (cur === row.evidence_id ? null : row.evidence_id))
              }
            />
          ))
        )}
      </section>
    </div>
  );
}