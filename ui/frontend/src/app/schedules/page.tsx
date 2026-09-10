"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge as UiBadge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet, apiPost, apiDelete } from "@/lib/api";
import { cn } from "@/lib/utils";
import { IconClock, IconTrash, IconPlayerPlay } from "@tabler/icons-react";

interface Schedule {
  id: number;
  target_id: number;
  cron: string;
  profile: string;
  max_destructive_level: string;
  allow_destructive: boolean;
  gate_mode: string;
  enabled: boolean;
  created_at: string;
  last_run_at: string | null;
  next_run_at: string | null;
}

interface Target {
  id: number;
  url: string;
  name: string | null;
}

export default function SchedulesPage() {
  const [schedules, setSchedules] = useState<Schedule[] | null>(null);
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({ target_id: "", cron: "0 2 * * *", profile: "passive" });
  const [creating, setCreating] = useState(false);

  function refresh() {
    apiGet<Schedule[]>("/api/schedules")
      .then(setSchedules)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }

  useEffect(() => {
    refresh();
    apiGet<Target[]>("/api/targets")
      .then(setTargets)
      .catch(() => {});
  }, []);

  async function handleCreate() {
    if (!form.target_id || !form.cron) return;
    setCreating(true);
    setError(null);
    try {
      await apiPost("/api/schedules", {
        target_id: Number(form.target_id),
        cron: form.cron,
        profile: form.profile,
      });
      refresh();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(id: number) {
    await apiDelete(`/api/schedules/${id}`);
    refresh();
  }

  async function handleTrigger(id: number) {
    await apiPost(`/api/schedules/${id}/trigger`);
    refresh();
  }

  return (
    <div className="space-y-8" data-testid="schedules-page">
      <header className="space-y-2">
        <h1 className="font-sans text-3xl font-semibold tracking-tight text-zinc-100">Schedules</h1>
        <p className="text-sm text-zinc-400">Cron-based auto scans. Cron format: min hour day month weekday (e.g. 0 2 * * *).</p>
      </header>

      <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
        <CardHeader className="pb-3">
          <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">New schedule</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-3">
            <select
              data-testid="schedule-target"
              value={form.target_id}
              onChange={(e) => setForm({ ...form, target_id: e.target.value })}
              className="rounded-lg border border-zinc-700 bg-zinc-800 p-2 text-sm text-zinc-100"
            >
              <option value="">Select target</option>
              {targets?.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name || t.url} (#{t.id})
                </option>
              ))}
            </select>
            <input
              data-testid="schedule-cron"
              value={form.cron}
              onChange={(e) => setForm({ ...form, cron: e.target.value })}
              placeholder="0 2 * * *"
              className="rounded-lg border border-zinc-700 bg-zinc-800 p-2 font-mono text-sm text-zinc-100"
            />
            <select
              data-testid="schedule-profile"
              value={form.profile}
              onChange={(e) => setForm({ ...form, profile: e.target.value })}
              className="rounded-lg border border-zinc-700 bg-zinc-800 p-2 text-sm text-zinc-100"
            >
              <option value="passive">passive</option>
              <option value="low_impact">low_impact</option>
              <option value="active">active</option>
            </select>
          </div>
          <Button data-testid="schedule-create" onClick={handleCreate} disabled={creating} className="gap-1.5">
            <IconClock size={14} /> {creating ? "Creating..." : "Create schedule"}
          </Button>
          {error ? (
            <div role="alert" data-testid="schedules-error" className="rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-300">
              {error}
            </div>
          ) : null}
        </CardContent>
      </Card>

      {schedules === null ? (
        <div className="space-y-3" data-testid="schedules-loading">
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
        </div>
      ) : schedules.length === 0 ? (
        <div data-testid="schedules-empty" className="rounded-xl border border-zinc-800 bg-zinc-900 p-6 text-center text-sm text-zinc-500">
          No schedules yet. Create one above.
        </div>
      ) : (
        <ul className="space-y-3" data-testid="schedules-rows">
          {schedules.map((s) => (
            <li key={s.id}>
              <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
                <CardContent className="flex items-start justify-between gap-4 p-0">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 font-mono text-sm text-zinc-100">
                      <IconClock size={14} className="text-zinc-500" /> {s.cron} <span className="text-zinc-500">·</span> {s.profile} <span className="text-zinc-500">·</span> target #{s.target_id}
                      <UiBadge variant="outline" className={cn("border", s.enabled ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-zinc-600/40 bg-zinc-800 text-zinc-400")}>
                        {s.enabled ? "enabled" : "disabled"}
                      </UiBadge>
                    </div>
                    <div className="text-xs text-zinc-500">
                      next: {s.next_run_at ? new Date(s.next_run_at).toLocaleString() : "—"} · last: {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "—"}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" data-testid={`schedule-trigger-${s.id}`} onClick={() => handleTrigger(s.id)} className="gap-1">
                      <IconPlayerPlay size={14} /> Run now
                    </Button>
                    <Button variant="outline" size="sm" data-testid={`schedule-delete-${s.id}`} onClick={() => handleDelete(s.id)} className="gap-1 text-red-300">
                      <IconTrash size={14} /> Delete
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
