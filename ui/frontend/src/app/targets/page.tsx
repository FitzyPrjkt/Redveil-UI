"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { IconPlus } from "@tabler/icons-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet } from "@/lib/api";

interface Target {
  id: number;
  url: string;
  name: string | null;
  scope_yaml: string | null;
  created_at: string | null;
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

export default function TargetsListPage() {
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  useEffect(() => {
    apiGet<Target[]>("/api/targets")
      .then((data) => setTargets(data))
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err));
      });
  }, []);

  const filtered = useMemo(() => {
    if (!targets) return [];
    const q = search.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter(
      (t) => t.url.toLowerCase().includes(q) || (t.name ?? "").toLowerCase().includes(q)
    );
  }, [targets, search]);

  return (
    <div className="space-y-8" data-testid="targets-list">
      <header className="flex items-center justify-between">
        <div>
          <h1
            className="font-sans text-3xl font-semibold tracking-tight text-zinc-100"
            data-testid="targets-list-title"
          >
            Targets
          </h1>
          <p className="text-sm text-zinc-400">
            Hosts you have configured scans against.
          </p>
        </div>
        <Link href="/targets/new">
          <Button data-testid="targets-new-button">
            <IconPlus className="h-4 w-4" />
            New target
          </Button>
        </Link>
      </header>

      {error && (
        <div
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
          role="alert"
          data-testid="targets-error"
        >
          Failed to load targets: {error}
        </div>
      )}

      <div className="flex items-center gap-3">
        <input
          type="search"
          placeholder="Filter by URL or name…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full max-w-md rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500"
          data-testid="targets-search"
        />
      </div>

      {targets === null && !error && (
        <div className="space-y-2" data-testid="targets-loading">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      )}

      {targets !== null && filtered.length === 0 && !error && (
        <div
          className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center"
          data-testid="targets-empty"
        >
          <p className="text-zinc-300">
            {search
              ? "No targets match this filter."
              : "No targets yet. Click \"New target\" to add one."}
          </p>
        </div>
      )}

      {filtered.length > 0 && (
        <ul className="space-y-2" data-testid="targets-rows">
          {filtered.map((t) => (
            <li key={t.id} data-testid={`target-row-${t.id}`}>
              <Link href={`/targets/${t.id}`}>
                <Card className="rounded-xl border border-zinc-800 bg-zinc-900 transition-colors hover:border-zinc-700">
                  <CardContent className="flex items-center gap-4 p-4">
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-sm text-zinc-100">
                        {t.name ?? t.url}
                      </div>
                      {t.name && (
                        <div className="truncate font-mono text-xs text-zinc-500">
                          {t.url}
                        </div>
                      )}
                    </div>
                    <div className="font-mono text-xs text-zinc-500">
                      {timeAgo(t.created_at)}
                    </div>
                  </CardContent>
                </Card>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
