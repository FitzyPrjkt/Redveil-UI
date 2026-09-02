"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import {
  IconAlertTriangle,
  IconChevronRight,
  IconFolder,
  IconRoute,
  IconShieldLock,
} from "@tabler/icons-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { apiGet } from "@/lib/api";
import { cn } from "@/lib/utils";

// --- Types --------------------------------------------------------------

interface Target {
  id: number;
  url: string;
  name: string | null;
}

interface SiteMapEndpoint {
  endpoint: string;
  method: string;
  finding_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  severity_counts: Record<string, number>;
}

interface SiteMap {
  target_id: number;
  target_url: string;
  endpoints: SiteMapEndpoint[];
  folders: string[];
}

interface Scope {
  allowed_hosts: string[];
  allowed_paths: string[];
  excluded_paths: string[];
  follow_redirects: boolean;
  max_redirects: number;
  raw_yaml: string | null;
}

interface IssueDefinition {
  id: string;
  name: string;
  check_id: string | null;
  severity: string;
  summary: string;
  cwe: string[];
  owasp: string[];
}

// --- Severity helpers ---------------------------------------------------

function severityBgClass(severity: string): string {
  switch (severity) {
    case "high":
    case "critical":
      return "bg-red-500/15 text-red-300";
    case "medium":
      return "bg-yellow-500/15 text-yellow-300";
    case "low":
      return "bg-blue-500/15 text-blue-300";
    default:
      return "bg-zinc-800 text-zinc-400";
  }
}

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case "high":
    case "critical":
      return "bg-red-500/15 text-red-300 border-red-500/20";
    case "medium":
      return "bg-yellow-500/15 text-yellow-300 border-yellow-500/20";
    case "low":
      return "bg-blue-500/15 text-blue-300 border-blue-500/20";
    default:
      return "bg-zinc-800 text-zinc-400 border-zinc-700";
  }
}

// --- Site Map tab -------------------------------------------------------

function SiteMapView({ data }: { data: SiteMap }) {
  // Group endpoints by their top-level folder (e.g. "/api" → /api/*).
  const grouped = useMemo(() => {
    const folders: Record<string, SiteMapEndpoint[]> = {};
    for (const ep of data.endpoints) {
      const seg = ep.endpoint.split("/").filter(Boolean)[0];
      const key = seg ? `/${seg}` : "/";
      if (!folders[key]) folders[key] = [];
      folders[key].push(ep);
    }
    return folders;
  }, [data.endpoints]);

  const folderKeys = Object.keys(grouped).sort();

  return (
    <div className="space-y-6" data-testid="sitemap-view">
      {folderKeys.length === 0 ? (
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-8 text-center text-sm text-zinc-500">
          No endpoints discovered yet. Run a scan to populate the site map.
        </Card>
      ) : (
        folderKeys.map((folder) => (
          <section key={folder} className="space-y-2">
            <div className="flex items-center gap-2 px-1">
              <IconFolder size={18} className="text-zinc-500" aria-hidden="true" />
              <code className="font-mono text-sm font-medium text-zinc-300">
                {folder}
              </code>
            </div>
            <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
              <ul className="divide-y divide-zinc-800">
                {grouped[folder].map((ep) => {
                  const badge = ep.high_count
                    ? { count: ep.high_count, severity: "high" }
                    : ep.medium_count
                      ? { count: ep.medium_count, severity: "medium" }
                      : null;
                  return (
                    <li
                      key={`${ep.method}-${ep.endpoint}`}
                      className="flex items-center gap-4 px-5 py-3"
                    >
                      <IconRoute
                        size={16}
                        className="shrink-0 text-zinc-500"
                        aria-hidden="true"
                      />
                      <code className="font-mono text-sm text-zinc-200">
                        {ep.endpoint}
                      </code>
                      <span className="ml-auto text-xs text-zinc-500">
                        {ep.method}
                      </span>
                      {badge ? (
                        <Badge
                          variant="outline"
                          className={cn(
                            "ml-2 min-w-7 justify-center border font-mono",
                            severityBadgeClass(badge.severity),
                          )}
                        >
                          {badge.count}
                        </Badge>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            </Card>
          </section>
        ))
      )}
    </div>
  );
}

// --- Scope tab ----------------------------------------------------------

function ScopeView({ data }: { data: Scope }) {
  return (
    <div className="space-y-6" data-testid="scope-view">
      <section className="space-y-3">
        <h3 className="text-xs font-medium uppercase tracking-wider text-zinc-500">
          Allowed hosts
        </h3>
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          {data.allowed_hosts.length === 0 ? (
            <p className="text-sm text-zinc-500">No host restrictions set.</p>
          ) : (
            <ul className="flex flex-wrap gap-2">
              {data.allowed_hosts.map((h) => (
                <li key={h}>
                  <code className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-xs text-zinc-300">
                    {h}
                  </code>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </section>

      <section className="space-y-3">
        <h3 className="text-xs font-medium uppercase tracking-wider text-zinc-500">
          Allowed paths
        </h3>
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          {data.allowed_paths.length === 0 ? (
            <p className="text-sm text-zinc-500">No path restrictions set.</p>
          ) : (
            <ul className="space-y-1">
              {data.allowed_paths.map((p) => (
                <li key={p} className="flex items-center gap-2">
                  <IconChevronRight
                    size={14}
                    className="text-zinc-500"
                    aria-hidden="true"
                  />
                  <code className="font-mono text-sm text-zinc-200">{p}</code>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </section>

      <section className="space-y-3">
        <h3 className="text-xs font-medium uppercase tracking-wider text-zinc-500">
          Excluded paths
        </h3>
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          {data.excluded_paths.length === 0 ? (
            <p className="text-sm text-zinc-500">
              No path exclusions. All allowed paths are scanned.
            </p>
          ) : (
            <ul className="space-y-1">
              {data.excluded_paths.map((p) => (
                <li key={p} className="flex items-center gap-2">
                  <IconAlertTriangle
                    size={14}
                    className="text-yellow-500"
                    aria-hidden="true"
                  />
                  <code className="font-mono text-sm text-zinc-200">{p}</code>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </section>

      <section className="space-y-3">
        <h3 className="text-xs font-medium uppercase tracking-wider text-zinc-500">
          Raw scope.yaml
        </h3>
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs text-zinc-400">
            {data.raw_yaml || "# (none — auto-allow on target URL)"}
          </pre>
        </Card>
      </section>

      <section className="space-y-3">
        <h3 className="text-xs font-medium uppercase tracking-wider text-zinc-500">
          Redirect policy
        </h3>
        <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <ul className="space-y-1 text-sm text-zinc-300">
            <li>
              Follow redirects:{" "}
              <span className="font-mono text-zinc-100">
                {data.follow_redirects ? "true" : "false"}
              </span>
            </li>
            <li>
              Max redirects:{" "}
              <span className="font-mono text-zinc-100">{data.max_redirects}</span>
            </li>
          </ul>
        </Card>
      </section>
    </div>
  );
}

// --- Issue Defs tab -----------------------------------------------------

function IssueDefsView({ items }: { items: IssueDefinition[] }) {
  if (items.length === 0) {
    return (
      <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-8 text-center text-sm text-zinc-500">
        No issue definitions registered.
      </Card>
    );
  }
  return (
    <div className="space-y-3" data-testid="issue-defs-view">
      {items.map((item) => (
        <Card
          key={item.id}
          className="flex items-start gap-4 rounded-xl border border-zinc-800 bg-zinc-900 p-5"
        >
          <IconShieldLock
            size={18}
            className="mt-0.5 shrink-0 text-zinc-500"
            aria-hidden="true"
          />
          <div className="flex-1 space-y-2">
            <div className="flex flex-wrap items-baseline gap-2">
              <code className="font-mono text-sm font-medium text-zinc-100">
                {item.id}
              </code>
              <span className="text-sm text-zinc-300">{item.name}</span>
              <Badge
                variant="outline"
                className={cn("ml-auto border", severityBadgeClass(item.severity))}
              >
                {item.severity}
              </Badge>
            </div>
            <p className="text-sm leading-relaxed text-zinc-400">{item.summary}</p>
            {(item.cwe.length > 0 || item.owasp.length > 0) && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {item.cwe.map((c) => (
                  <span
                    key={c}
                    className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-0.5 font-mono text-[10px] text-zinc-400"
                  >
                    {c}
                  </span>
                ))}
                {item.owasp.map((o) => (
                  <span
                    key={o}
                    className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-0.5 font-mono text-[10px] text-zinc-400"
                  >
                    OWASP {o}
                  </span>
                ))}
              </div>
            )}
          </div>
        </Card>
      ))}
    </div>
  );
}

// --- Page ---------------------------------------------------------------

export default function TargetDetailPage() {
  const params = useParams<{ id: string }>();
  const targetId = params?.id;
  const [target, setTarget] = useState<Target | null>(null);
  const [sitemap, setSitemap] = useState<SiteMap | null>(null);
  const [scope, setScope] = useState<Scope | null>(null);
  const [issueDefs, setIssueDefs] = useState<IssueDefinition[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!targetId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      apiGet<Target>(`/api/targets/${targetId}`),
      apiGet<SiteMap>(`/api/targets/${targetId}/sitemap`),
      apiGet<Scope>(`/api/targets/${targetId}/scope`),
      apiGet<IssueDefinition[]>(`/api/issue-definitions`),
    ])
      .then(([t, s, sc, ids]) => {
        if (cancelled) return;
        setTarget(t);
        setSitemap(s);
        setScope(sc);
        setIssueDefs(ids);
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
  }, [targetId]);

  if (loading && !target) {
    return (
      <div className="space-y-8">
        <header className="space-y-2">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-72" />
        </header>
        <Skeleton className="h-9 w-72" />
        <Skeleton className="h-48 w-full rounded-xl bg-zinc-900" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <header className="space-y-2">
          <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
            Target
          </h1>
        </header>
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
        >
          Failed to load target: {error}
        </div>
      </div>
    );
  }

  if (!target) return null;

  return (
    <div className="space-y-8" data-testid="target-page">
      <header className="space-y-2">
        <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
          Target
        </h1>
        <code className="block font-mono text-sm text-zinc-400">
          {target.url}
        </code>
        {target.name ? (
          <p className="text-xs text-zinc-500">
            alias: <span className="font-mono text-zinc-400">{target.name}</span>
          </p>
        ) : null}
      </header>

      <Tabs defaultValue="sitemap" className="space-y-6">
        <TabsList variant="line">
          <TabsTrigger value="sitemap">Site map</TabsTrigger>
          <TabsTrigger value="scope">Scope</TabsTrigger>
          <TabsTrigger value="issue-defs">Issue defs</TabsTrigger>
        </TabsList>

        <TabsContent value="sitemap" className="outline-none">
          {sitemap ? (
            <SiteMapView data={sitemap} />
          ) : (
            <Skeleton className="h-48 w-full rounded-xl bg-zinc-900" />
          )}
        </TabsContent>
        <TabsContent value="scope" className="outline-none">
          {scope ? (
            <ScopeView data={scope} />
          ) : (
            <Skeleton className="h-48 w-full rounded-xl bg-zinc-900" />
          )}
        </TabsContent>
        <TabsContent value="issue-defs" className="outline-none">
          <IssueDefsView items={issueDefs} />
        </TabsContent>
      </Tabs>
    </div>
  );
}