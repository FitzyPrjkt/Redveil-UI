"use client";

import { useState } from "react";
import {
  IconAlertTriangle,
  IconCircleCheck,
  IconLock,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { apiPost } from "@/lib/api";
import { cn } from "@/lib/utils";

type Verdict = "weak" | "marginal" | "ok";

interface EntropyResult {
  bits_per_char: number;
  length: number;
  verdict: Verdict;
  confirmed_threshold: number;
  likely_threshold: number;
}

function verdictClasses(v: Verdict): {
  wrap: string;
  text: string;
  label: string;
} {
  switch (v) {
    case "weak":
      return {
        wrap: "border-red-500/30 bg-red-500/10 text-red-300",
        text: "text-red-300",
        label: "weak",
      };
    case "marginal":
      return {
        wrap: "border-yellow-500/30 bg-yellow-500/10 text-yellow-300",
        text: "text-yellow-300",
        label: "marginal",
      };
    case "ok":
      return {
        wrap: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
        text: "text-emerald-300",
        label: "ok",
      };
  }
}

function verdictCopy(
  v: Verdict,
  confirmed: number,
  likely: number,
  bits: number,
): string {
  const rounded = bits.toFixed(2);
  switch (v) {
    case "weak":
      return `Weak — below ${confirmed.toFixed(1)} bits/char threshold (got ${rounded}). Token is predictable.`;
    case "marginal":
      return `Marginal — between ${confirmed.toFixed(1)} and ${likely.toFixed(1)} bits/char (got ${rounded}). Acceptable but room to improve.`;
    case "ok":
      return `Strong — at or above ${likely.toFixed(1)} bits/char (got ${rounded}). Token entropy is healthy.`;
  }
}

export default function TokenEntropyPage() {
  const [value, setValue] = useState("a1b2c3d4e5f6...");
  const [result, setResult] = useState<EntropyResult | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze(e?: React.FormEvent) {
    e?.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const r = await apiPost<EntropyResult>("/api/entropy/analyze", { value });
      setResult(r);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      setResult(null);
    } finally {
      setSubmitting(false);
    }
  }

  const verdict = result ? verdictClasses(result.verdict) : null;

  // Sparkline: a horizontal bar of entropy vs thresholds. Pure SVG so we
  // don't pull a charting dep for one widget.
  const chart = result
    ? (() => {
        // Cap visual range at 5 bits/char — well past the "ok" threshold.
        const max = 5;
        const bits = Math.min(result.bits_per_char, max);
        const confirmed = Math.min(result.confirmed_threshold, max);
        const likely = Math.min(result.likely_threshold, max);
        return (
          <div className="space-y-2">
            <div className="relative h-3 w-full overflow-hidden rounded-full bg-zinc-900">
              <div
                className="absolute inset-y-0 left-0 bg-emerald-500/20"
                style={{ width: `${(likely / max) * 100}%` }}
              />
              <div
                className="absolute inset-y-0 left-0 bg-red-500/30"
                style={{ width: `${(confirmed / max) * 100}%` }}
              />
              <div
                data-testid="entropy-bar"
                className={cn(
                  "absolute inset-y-0 left-0 transition-all",
                  result.verdict === "weak" && "bg-red-500",
                  result.verdict === "marginal" && "bg-yellow-500",
                  result.verdict === "ok" && "bg-emerald-500",
                )}
                style={{ width: `${(bits / max) * 100}%` }}
              />
            </div>
            <div className="flex justify-between text-[10px] font-mono text-zinc-500">
              <span>0</span>
              <span>
                weak&nbsp;≤&nbsp;{result.confirmed_threshold.toFixed(1)}
              </span>
              <span>
                strong&nbsp;≥&nbsp;{result.likely_threshold.toFixed(1)}
              </span>
              <span>{max.toFixed(1)}</span>
            </div>
          </div>
        );
      })()
    : null;

  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <header className="space-y-2">
        <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
          Token entropy
        </h1>
        <p className="text-sm text-zinc-400">
          Paste a session cookie, CSRF token, or any opaque string. The
          backend computes Shannon entropy using the same
          {" "}<span className="font-mono text-zinc-300">shannon_entropy</span>{" "}
          function the session-cookie check uses, then maps the result against
          the {" "}<span className="font-mono text-zinc-300">_ENTROPY_CONFIRMED</span>
          {" / "}<span className="font-mono text-zinc-300">_ENTROPY_LIKELY</span>
          {" "}thresholds.
        </p>
      </header>

      <form onSubmit={handleAnalyze} className="space-y-6">
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <div className="space-y-3">
            <label
              htmlFor="token"
              className="text-sm font-medium text-zinc-300"
            >
              Token sample
            </label>
            <textarea
              id="token"
              data-testid="entropy-input"
              rows={3}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              spellCheck={false}
              className="w-full resize-y rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-500 focus:outline-none"
              placeholder="paste a token or cookie value"
            />
            <div className="flex items-center justify-between">
              <span className="text-xs text-zinc-500">
                {value.length} chars
              </span>
              <Button
                type="submit"
                disabled={submitting || value.length === 0}
                data-testid="entropy-submit"
                className="gap-1.5"
              >
                {submitting ? (
                  "Analyzing…"
                ) : (
                  <>
                    <IconLock size={14} aria-hidden="true" />
                    Analyze
                  </>
                )}
              </Button>
            </div>
          </div>
        </Card>

        {error ? (
          <div
            role="alert"
            data-testid="entropy-error"
            className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
          >
            {error}
          </div>
        ) : null}

        {result && verdict ? (
          <div
            data-testid="entropy-result"
            className="space-y-4"
          >
            {/* Stat blocks */}
            <div className="grid gap-4 sm:grid-cols-2">
              <Card className="rounded-lg border-0 bg-zinc-950 p-5">
                <CardContent className="space-y-1 p-0">
                  <div className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                    Entropy
                  </div>
                  <div
                    data-testid="entropy-bits"
                    className="text-3xl font-bold text-zinc-100"
                  >
                    {result.bits_per_char.toFixed(2)}
                    <span className="ml-1 text-base font-normal text-zinc-500">
                      bits/char
                    </span>
                  </div>
                </CardContent>
              </Card>

              <Card className="rounded-lg border-0 bg-zinc-950 p-5">
                <CardContent className="space-y-1 p-0">
                  <div className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                    Length
                  </div>
                  <div
                    data-testid="entropy-length"
                    className="text-3xl font-bold text-zinc-100"
                  >
                    {result.length}
                    <span className="ml-1 text-base font-normal text-zinc-500">
                      chars
                    </span>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Sparkline */}
            <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
              <div className="space-y-2">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">
                  Entropy scale
                </h3>
                {chart}
              </div>
            </Card>

            {/* Verdict */}
            <div
              role="alert"
              data-testid="entropy-verdict"
              className={cn(
                "flex items-start gap-3 rounded-lg border p-4 text-sm",
                verdict.wrap,
              )}
            >
              {result.verdict === "ok" ? (
                <IconCircleCheck
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
              <span className={cn("font-medium", verdict.text)}>
                {verdictCopy(
                  result.verdict,
                  result.confirmed_threshold,
                  result.likely_threshold,
                  result.bits_per_char,
                )}
              </span>
            </div>
          </div>
        ) : null}
      </form>
    </div>
  );
}