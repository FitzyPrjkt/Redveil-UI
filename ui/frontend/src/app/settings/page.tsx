"use client";

import { useEffect, useMemo, useState } from "react";
import {
  IconAlertTriangle,
  IconKey,
  IconRefresh,
  IconReportAnalytics,
  IconShieldLock,
  IconAdjustments,
  IconUserShield,
} from "@tabler/icons-react";
import type { IconProps } from "@tabler/icons-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";

type GateMode = "interactive" | "non_interactive" | "strict";
type Profile = "passive" | "low_impact" | "active";
type FormatKind = "markdown" | "json" | "html";

interface ActiveConfig {
  limits: {
    requests_per_second: number;
    max_requests: number;
    timeout_seconds: number;
    max_response_size_bytes: number;
    max_concurrent_requests: number;
    connection_pool_size: number;
  };
  authorization: {
    active_testing: boolean;
    allow_destructive: boolean;
    max_destructive_level: number;
    acknowledged_safety_terms: boolean;
    out_of_band_callback_domain: string | null;
  };
  reporting: {
    output_dir: string;
    formats: FormatKind[];
    redact_secrets: boolean;
  };
  auth: {
    method: string;
    principals: { name: string; auth_method: string }[];
  };
  defaults: {
    gate_mode: GateMode;
    profile: Profile;
  };
}

const ACTIVE_RECOMMENDED_MIN = 1500;

const GATE_OPTIONS: { value: GateMode; label: string; description: string }[] = [
  {
    value: "non_interactive",
    label: "Non-interactive (CI/automated)",
    description: "auto-approve, log everything",
  },
  {
    value: "strict",
    label: "Strict (deny MEDIUM+)",
    description: "deny any MEDIUM+ action automatically",
  },
  {
    value: "interactive",
    label: "Interactive",
    description: "prompts per action via WebSocket (coming in v2)",
  },
];

const PROFILE_OPTIONS: { value: Profile; label: string; description: string }[] = [
  { value: "passive", label: "passive", description: "read-only recon" },
  { value: "low_impact", label: "low_impact", description: "non-destructive probes" },
  { value: "active", label: "active", description: "exploitation-grade" },
];

const FORMAT_OPTIONS: FormatKind[] = ["markdown", "json", "html"];

type IconComponent = React.ComponentType<IconProps>;

function SectionHeader({
  Icon,
  title,
  hint,
}: {
  Icon: IconComponent;
  title: string;
  hint: string;
}) {
  return (
    <div className="flex items-start gap-3 border-b border-zinc-800 px-5 py-4">
      <Icon size={18} className="mt-0.5 shrink-0 text-zinc-500" aria-hidden="true" />
      <div className="space-y-0.5">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-200">
          {title}
        </h2>
        <p className="text-xs text-zinc-500">{hint}</p>
      </div>
    </div>
  );
}

function StatTile({
  label,
  value,
  unit,
  tone,
}: {
  label: string;
  value: string;
  unit?: string;
  tone?: "neutral" | "warn" | "danger";
}) {
  return (
    <div className="space-y-1 rounded-lg bg-zinc-950 px-3 py-2.5">
      <div className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
        {label}
      </div>
      <div className="flex items-baseline gap-1.5">
        <span
          className={cn(
            "font-mono text-base font-semibold",
            tone === "warn" && "text-yellow-300",
            tone === "danger" && "text-red-300",
            (!tone || tone === "neutral") && "text-zinc-100",
          )}
        >
          {value}
        </span>
        {unit ? <span className="text-xs text-zinc-500">{unit}</span> : null}
      </div>
    </div>
  );
}

function ConfigSkeleton() {
  return (
    <div className="space-y-6">
      {Array.from({ length: 4 }).map((_, i) => (
        <Card
          key={i}
          className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900"
        >
          <Skeleton className="h-14 w-full bg-zinc-900" />
          <div className="space-y-3 p-5">
            <Skeleton className="h-6 w-full bg-zinc-900" />
            <Skeleton className="h-6 w-3/4 bg-zinc-900" />
            <Skeleton className="h-6 w-2/3 bg-zinc-900" />
          </div>
        </Card>
      ))}
    </div>
  );
}

function formatBytes(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)} KB`;
  return `${n} B`;
}

function destructiveLabel(level: number): string {
  const names = [
    "",
    "L1 — Data Exfiltration",
    "L2 — Data Modification",
    "L3 — Data Destruction",
    "L4 — Persistence",
    "L5 — Lateral Movement",
    "L6 — Takeover",
  ];
  return names[level] ?? `L${level}`;
}

function destructiveColor(level: number): string {
  if (level <= 2) return "bg-yellow-500/15 text-yellow-300 border-yellow-500/30";
  if (level <= 4) return "bg-orange-500/15 text-orange-300 border-orange-500/30";
  return "bg-red-500/15 text-red-300 border-red-500/30";
}

function authMethodBadge(method: string): string {
  if (method === "none") return "bg-zinc-800 text-zinc-400 border-zinc-700";
  if (method === "cookie") return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
  if (method === "bearer") return "bg-sky-500/10 text-sky-400 border-sky-500/20";
  if (method === "basic") return "bg-violet-500/10 text-violet-400 border-violet-500/20";
  if (method === "custom_header")
    return "bg-orange-500/10 text-orange-400 border-orange-500/20";
  return "bg-zinc-800 text-zinc-300 border-zinc-700";
}

export default function SettingsPage() {
  const [cfg, setCfg] = useState<ActiveConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGet<ActiveConfig>("/api/config");
      setCfg(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const belowActiveMin = useMemo(() => {
    if (!cfg) return false;
    return cfg.limits.max_requests < ACTIVE_RECOMMENDED_MIN;
  }, [cfg]);

  const destructiveEnabled = cfg?.authorization.allow_destructive ?? false;
  const activeTesting = cfg?.authorization.active_testing ?? false;
  const acknowledged = cfg?.authorization.acknowledged_safety_terms ?? false;

  const destructiveCompliance: { ok: boolean; reason: string } = useMemo(() => {
    if (!cfg) return { ok: true, reason: "" };
    if (!cfg.authorization.allow_destructive) return { ok: true, reason: "" };
    if (!cfg.authorization.active_testing)
      return { ok: false, reason: "requires active_testing=true" };
    if (!cfg.authorization.acknowledged_safety_terms)
      return {
        ok: false,
        reason: "requires acknowledged_safety_terms=true",
      };
    return { ok: true, reason: "" };
  }, [cfg]);

  return (
    <div className="space-y-8">
      <header className="flex items-start justify-between gap-4">
        <div className="space-y-2">
          <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
            Settings
          </h1>
          <p className="text-sm text-zinc-400">
            Active redveil config — limits, authorization gates, reporting, and
            authentication material applied to new scans.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={async () => {
            setResetting(true);
            await load();
            setResetting(false);
          }}
          disabled={loading || resetting}
          data-testid="settings-refresh"
        >
          <IconRefresh size={14} aria-hidden="true" />
          {resetting ? "Reloading…" : "Refresh"}
        </Button>
      </header>

      {error ? (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
        >
          Failed to load active config: {error}
        </div>
      ) : null}

      {loading && !cfg ? <ConfigSkeleton /> : null}

      {cfg ? (
        <div className="space-y-6">
          {/* Limits */}
          <Card
            data-testid="settings-section-limits"
            className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900"
          >
            <SectionHeader
              Icon={IconAdjustments}
              title="Limits"
              hint="Network and resource budgets applied by the HTTP client."
            />
            <div className="space-y-5 p-5">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <StatTile
                  label="Max requests"
                  value={String(cfg.limits.max_requests)}
                  tone={belowActiveMin ? "warn" : "neutral"}
                />
                <StatTile
                  label="Requests / second"
                  value={cfg.limits.requests_per_second.toFixed(1)}
                  unit="rps"
                />
                <StatTile
                  label="Timeout"
                  value={cfg.limits.timeout_seconds.toFixed(1)}
                  unit="sec"
                />
                <StatTile
                  label="Max response size"
                  value={formatBytes(cfg.limits.max_response_size_bytes)}
                />
                <StatTile
                  label="Concurrent requests"
                  value={String(cfg.limits.max_concurrent_requests)}
                />
                <StatTile
                  label="Connection pool"
                  value={String(cfg.limits.connection_pool_size)}
                />
              </div>
              {belowActiveMin ? (
                <div
                  role="alert"
                  data-testid="limits-below-active-min"
                  className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm text-yellow-300"
                >
                  <IconAlertTriangle
                    size={16}
                    className="mt-0.5 shrink-0"
                    aria-hidden="true"
                  />
                  <span>
                    Max requests {cfg.limits.max_requests} is below the
                    recommended minimum{" "}
                    <span className="font-mono">{ACTIVE_RECOMMENDED_MIN}</span>{" "}
                    for active profile checks (Time-Based SQLi 640 + Command
                    Injection 1190 worst case). Active scans will be cut off
                    mid-probe.
                  </span>
                </div>
              ) : null}
            </div>
          </Card>

          {/* Authorization */}
          <Card
            data-testid="settings-section-authorization"
            className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900"
          >
            <SectionHeader
              Icon={IconShieldLock}
              title="Authorization"
              hint="Explicit gates for invasive behavior. Mutating these values
              is deferred until validation lands."
            />
            <div className="space-y-5 p-5">
              <dl className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1">
                  <dt className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                    Default gate mode
                  </dt>
                  <dd
                    className="font-mono text-sm text-zinc-100"
                    data-testid="auth-gate-mode"
                  >
                    {cfg.defaults.gate_mode}
                  </dd>
                  <dd className="text-xs text-zinc-500">
                    {
                      GATE_OPTIONS.find((o) => o.value === cfg.defaults.gate_mode)
                        ?.description
                    }
                  </dd>
                </div>

                <div className="space-y-1">
                  <dt className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                    Default scan profile
                  </dt>
                  <dd className="font-mono text-sm text-zinc-100">
                    {cfg.defaults.profile}
                  </dd>
                  <dd className="text-xs text-zinc-500">
                    {
                      PROFILE_OPTIONS.find(
                        (o) => o.value === cfg.defaults.profile,
                      )?.description
                    }
                  </dd>
                </div>

                <div className="space-y-1">
                  <dt className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                    Max destructive level
                  </dt>
                  <dd className="flex items-center gap-2 pt-0.5">
                    <span
                      aria-hidden="true"
                      className={cn(
                        "h-2.5 w-2.5 shrink-0 rounded-full border",
                        destructiveColor(cfg.authorization.max_destructive_level),
                      )}
                    />
                    <span
                      className={cn(
                        "rounded-full border px-2 py-0.5 font-mono text-xs",
                        destructiveColor(cfg.authorization.max_destructive_level),
                      )}
                      data-testid="auth-max-destructive"
                    >
                      {destructiveLabel(cfg.authorization.max_destructive_level)}
                    </span>
                  </dd>
                </div>

                <div className="space-y-1">
                  <dt className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                    Active testing
                  </dt>
                  <dd
                    className={cn(
                      "font-mono text-sm",
                      activeTesting ? "text-red-300" : "text-zinc-100",
                    )}
                  >
                    {activeTesting ? "enabled" : "disabled"}
                  </dd>
                  <dd className="text-xs text-zinc-500">
                    Read-only — toggled via the YAML config file.
                  </dd>
                </div>
              </dl>

              <div className="space-y-2">
                <dt className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                  Allow destructive actions
                </dt>
                <dd className="flex items-center gap-2">
                  <span
                    className={cn(
                      "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs",
                      destructiveEnabled
                        ? "border-red-500/30 bg-red-500/10 text-red-300"
                        : "border-zinc-700 bg-zinc-800 text-zinc-400",
                    )}
                  >
                    {destructiveEnabled ? "on" : "off"}
                  </span>
                  {cfg.authorization.out_of_band_callback_domain ? (
                    <span className="font-mono text-xs text-zinc-400">
                      OOB: {cfg.authorization.out_of_band_callback_domain}
                    </span>
                  ) : null}
                </dd>
                {!destructiveCompliance.ok ? (
                  <div
                    role="alert"
                    className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
                  >
                    <IconAlertTriangle
                      size={16}
                      className="mt-0.5 shrink-0"
                      aria-hidden="true"
                    />
                    <span>
                      Destructive actions are flagged on but config fails the
                      safety check ({destructiveCompliance.reason}). The
                      framework will refuse destructive actions at scan time
                      regardless of this flag.
                    </span>
                  </div>
                ) : null}
                {acknowledged ? (
                  <p className="text-xs text-zinc-500">
                    Safety terms acknowledged.
                  </p>
                ) : (
                  <p className="text-xs text-zinc-500">
                    Safety terms NOT acknowledged — destructive actions will be
                    denied even if enabled.
                  </p>
                )}
              </div>
            </div>
          </Card>

          {/* Reporting */}
          <Card
            data-testid="settings-section-reporting"
            className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900"
          >
            <SectionHeader
              Icon={IconReportAnalytics}
              title="Reporting"
              hint="Where scan reports are written and which formats are produced."
            />
            <div className="space-y-5 p-5">
              <div className="space-y-1">
                <dt className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                  Output directory
                </dt>
                <dd
                  className="break-all rounded-lg bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100"
                  data-testid="reporting-output-dir"
                >
                  {cfg.reporting.output_dir}
                </dd>
              </div>

              <div className="space-y-2">
                <dt className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                  Formats
                </dt>
                <dd className="flex flex-wrap items-center gap-1.5">
                  {FORMAT_OPTIONS.map((fmt) => {
                    const enabled = cfg.reporting.formats.includes(fmt);
                    return (
                      <span
                        key={fmt}
                        className={cn(
                          "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-xs",
                          enabled
                            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                            : "border-zinc-700 bg-zinc-800 text-zinc-500 line-through",
                        )}
                      >
                        {fmt}
                      </span>
                    );
                  })}
                </dd>
              </div>

              <div className="flex items-center gap-2">
                <dt className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                  Redact secrets
                </dt>
                <dd
                  className={cn(
                    "font-mono text-sm",
                    cfg.reporting.redact_secrets
                      ? "text-emerald-300"
                      : "text-zinc-400",
                  )}
                >
                  {cfg.reporting.redact_secrets ? "on" : "off"}
                </dd>
              </div>
            </div>
          </Card>

          {/* Auth (read-only) */}
          <Card
            data-testid="settings-section-auth"
            className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900"
          >
            <SectionHeader
              Icon={IconUserShield}
              title="Auth"
              hint="Authentication material applied to every outbound request.
              Sensitive values are never exposed via this view."
            />
            <div className="space-y-5 p-5">
              <div className="flex items-center gap-2">
                <IconKey size={14} className="text-zinc-500" aria-hidden="true" />
                <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                  Default auth method
                </span>
                <span
                  className={cn(
                    "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-xs",
                    authMethodBadge(cfg.auth.method),
                  )}
                  data-testid="auth-method"
                >
                  {cfg.auth.method}
                </span>
              </div>

              <div className="space-y-2">
                <dt className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">
                  Principals{" "}
                  <span className="text-zinc-600">({cfg.auth.principals.length})</span>
                </dt>
                {cfg.auth.principals.length === 0 ? (
                  <p className="rounded-lg bg-zinc-950 px-3 py-2 text-xs text-zinc-500">
                    No multi-principal accounts configured. BOLA / IDOR checks
                    run in single-principal mode.
                  </p>
                ) : (
                  <ul
                    className="divide-y divide-zinc-800 overflow-hidden rounded-lg border border-zinc-800"
                    data-testid="auth-principals"
                  >
                    {cfg.auth.principals.map((p) => (
                      <li
                        key={p.name}
                        className="flex items-center justify-between bg-zinc-950 px-3 py-2 text-sm"
                      >
                        <span className="font-mono text-zinc-100">{p.name}</span>
                        <span
                          className={cn(
                            "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-xs",
                            authMethodBadge(p.auth_method),
                          )}
                        >
                          {p.auth_method}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </Card>

          <p className="pt-2 text-center text-xs text-zinc-500">
            View-only — config edits land after per-field validation is in
            place. Toggling destructive flags in a running scan can brick
            in-flight checks.
          </p>
        </div>
      ) : null}
    </div>
  );
}