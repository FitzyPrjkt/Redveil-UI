"use client";

import { useEffect, useMemo, useState } from "react";
import type { IconProps } from "@tabler/icons-react";
import {
  IconAffiliate,
  IconBinaryTree,
  IconCircleDashed,
  IconCloudDownload,
  IconCode,
  IconCookie,
  IconDatabase,
  IconEye,
  IconFolder,
  IconForms,
  IconHttpConnect,
  IconLock,
  IconMap,
  IconRoute,
  IconShield,
  IconShieldLock,
  IconShieldOff,
  IconTerminal,
  IconWorld,
} from "@tabler/icons-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";

type SafetyProfile = "passive" | "low_impact" | "active";
type FilterValue = "all" | SafetyProfile;

interface CheckOut {
  id: string;
  name: string;
  category: string;
  safety_profile: SafetyProfile;
  description: string;
  max_risk?: string;
  version: string;
}

type IconComponent = React.ComponentType<IconProps>;

const ICONS: Record<string, IconComponent> = {
  "xss-reflected": IconCode,
  "sqli-time-based": IconDatabase,
  ssrf: IconCloudDownload,
  "command-injection": IconTerminal,
  "path-traversal": IconFolder,
  "bola-idor": IconLock,
  bfla: IconShieldLock,
  "bfla-behavior": IconShieldLock,
  graphql: IconBinaryTree,
  "session-cookie": IconCookie,
  "session-invalidation": IconShieldOff,
  "mass-assignment": IconForms,
  "open-redirect-indicator": IconRoute,
  "http-methods": IconHttpConnect,
  "cors-policy": IconWorld,
  "security-headers": IconShield,
  "information-disclosure": IconEye,
  "source-map-exposure": IconMap,
  "subdomain-finder": IconAffiliate,
  "ssrf-behavior": IconCloudDownload,
};

const FALLBACK_ICON: IconComponent = IconCircleDashed;

const PROFILE_STYLES: Record<SafetyProfile, string> = {
  passive: "bg-zinc-800 text-zinc-300",
  low_impact: "bg-orange-500/15 text-orange-300",
  active: "bg-red-500/15 text-red-300",
};

const PROFILE_LABEL: Record<SafetyProfile, string> = {
  passive: "passive",
  low_impact: "low_impact",
  active: "active",
};

const FILTERS: { value: FilterValue; label: string }[] = [
  { value: "all", label: "All" },
  { value: "passive", label: "Passive" },
  { value: "low_impact", label: "Low impact" },
  { value: "active", label: "Active" },
];

function ProfileBadge({ profile }: { profile: SafetyProfile }) {
  return (
    <span
      className={cn(
        "shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium tracking-wide",
        PROFILE_STYLES[profile],
      )}
    >
      {PROFILE_LABEL[profile]}
    </span>
  );
}

function CheckCard({ check }: { check: CheckOut }) {
  const Icon = ICONS[check.id] ?? FALLBACK_ICON;
  return (
    <Card
      data-testid="check-card"
      className="flex h-full flex-col items-start justify-between gap-6 rounded-xl border border-zinc-800 bg-zinc-900 p-5"
    >
      <Icon className="size-7 shrink-0 text-zinc-500" aria-hidden="true" />
      <div className="flex flex-col items-start gap-2">
        <code className="font-mono text-sm font-medium text-zinc-100">
          {check.id}
        </code>
        <ProfileBadge profile={check.safety_profile} />
      </div>
    </Card>
  );
}

function CardSkeleton() {
  return (
    <Skeleton
      data-testid="check-card-skeleton"
      className="h-[112px] w-full rounded-xl bg-zinc-900"
    />
  );
}

export default function PluginsPage() {
  const [checks, setChecks] = useState<CheckOut[]>([]);
  const [filter, setFilter] = useState<FilterValue>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    apiGet<CheckOut[]>("/api/checks")
      .then((data) => {
        if (!cancelled) setChecks(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const message = err instanceof Error ? err.message : String(err);
          setError(message);
          console.error("Failed to load checks", err);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered = useMemo(() => {
    if (filter === "all") return checks;
    return checks.filter((c) => c.safety_profile === filter);
  }, [checks, filter]);

  return (
    <div className="space-y-8">
      <header className="space-y-2">
        <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
          Plugins
        </h1>
        <p className="text-sm text-zinc-400">
          {checks.length > 0
            ? `grid ${checks.length} checks dengan safety profile & filter`
            : "grid checks dengan safety profile & filter"}
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-2">
        {FILTERS.map((opt) => {
          const selected = filter === opt.value;
          return (
            <Button
              key={opt.value}
              size="sm"
              variant={selected ? "default" : "outline"}
              aria-pressed={selected}
              onClick={() => setFilter(opt.value)}
            >
              {opt.label}
            </Button>
          );
        })}
      </div>

      {error ? (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          Failed to load checks: {error}
        </div>
      ) : null}

      <section
        className="grid grid-cols-1 gap-4 md:grid-cols-2"
        data-testid="checks-grid"
      >
        {loading
          ? Array.from({ length: 6 }).map((_, i) => <CardSkeleton key={i} />)
          : filtered.map((check) => <CheckCard key={check.id} check={check} />)}
      </section>

      <p className="pt-4 text-center text-sm text-zinc-500">
        {loading
          ? "loading checks…"
          : `${checks.length} checks registered`}
      </p>
    </div>
  );
}