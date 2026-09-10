"use client";

import { useEffect, useState } from "react";
import { IconKey, IconAlertTriangle, IconCircleCheck, IconPlus, IconTrash, IconTestPipe } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiGet, apiPut, apiPost } from "@/lib/api";

interface ExtractConfig {
  from: string;
  regex: string;
  header_name?: string;
  json_path?: string;
}

interface InjectConfig {
  to: string;
  name: string;
}

interface RuleConfig {
  name: string;
  extract_url: string;
  extract: ExtractConfig;
  inject: InjectConfig;
  scope?: string;
  ttl_seconds: number;
}

interface SessionConfig {
  rules: RuleConfig[];
  reauth: {
    enabled: boolean;
    login_url?: string;
    login_method?: string;
    login_body?: string;
    login_headers?: Record<string, string>;
    max_retries?: number;
  };
}

const defaultRule: RuleConfig = {
  name: "csrf",
  extract_url: "https://example.com/login",
  extract: { from: "body", regex: 'name="csrf" value="([^"]+)"' },
  inject: { to: "header", name: "X-CSRF-Token" },
  scope: "",
  ttl_seconds: 300,
};

export default function SessionRulesPage() {
  const [config, setConfig] = useState<SessionConfig>({ rules: [], reauth: { enabled: false } });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<Record<number, { token?: string; error?: string; status?: number }>>({});

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const data = await apiGet<SessionConfig>("/api/session-rules");
        if (!cancelled) setConfig(data && typeof data === "object" ? { rules: (data as SessionConfig).rules || [], reauth: (data as SessionConfig).reauth || { enabled: false } } : { rules: [], reauth: { enabled: false } });
      } catch {
        // leave default
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  async function handleSave() {
    setError(null);
    setSuccess(null);
    setSaving(true);
    try {
      const payload: SessionConfig = {
        rules: config.rules.map((r) => ({
          ...r,
          scope: r.scope?.trim() || undefined,
        })),
        reauth: config.reauth,
      };
      const res = await apiPut<SessionConfig>("/api/session-rules", payload);
      setConfig(res);
      setSuccess("Saved");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleTest(idx: number) {
    const rule = config.rules[idx];
    try {
      const res = await apiPost<{ token?: string; extracted: boolean; preview?: string; error?: string; status_code?: number }>("/api/session-rules/test", {
        extract_url: rule.extract_url,
        extract: rule.extract,
        inject: rule.inject,
      });
      setTestResult((prev) => ({ ...prev, [idx]: { token: res.token, error: res.error, status: res.status_code } }));
    } catch (e: unknown) {
      setTestResult((prev) => ({ ...prev, [idx]: { error: e instanceof Error ? e.message : String(e) } }));
    }
  }

  function updateRule(idx: number, patch: Partial<RuleConfig>) {
    setConfig((prev) => {
      const rules = [...prev.rules];
      rules[idx] = { ...rules[idx], ...patch };
      return { ...prev, rules };
    });
  }

  function updateExtract(idx: number, patch: Partial<ExtractConfig>) {
    setConfig((prev) => {
      const rules = [...prev.rules];
      rules[idx] = { ...rules[idx], extract: { ...rules[idx].extract, ...patch } as ExtractConfig };
      return { ...prev, rules };
    });
  }

  function updateInject(idx: number, patch: Partial<InjectConfig>) {
    setConfig((prev) => {
      const rules = [...prev.rules];
      rules[idx] = { ...rules[idx], inject: { ...rules[idx].inject, ...patch } as InjectConfig };
      return { ...prev, rules };
    });
  }

  if (loading) return <p className="text-sm text-zinc-500">Loading…</p>;

  return (
    <div className="mx-auto max-w-5xl space-y-8" data-testid="session-rules-page">
      <header className="space-y-2">
        <h1 className="flex items-center gap-2 font-sans text-3xl font-semibold tracking-tight text-zinc-100">
          <IconKey size={24} className="text-zinc-400" />
          Session Rules
        </h1>
        <p className="text-sm text-zinc-400">
          Extraction rule <span className="font-mono text-zinc-300">regex</span> dari response <span className="font-mono">body/header/json</span> → inject <span className="font-mono">header/cookie</span> per <span className="font-mono">scope</span> + TTL, + reauth. Workflow iteratif — test sebelum save.
        </p>
      </header>

      <Card className="space-y-4 rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Rules</h2>
          <Button
            onClick={() => setConfig((prev) => ({ ...prev, rules: [...prev.rules, { ...defaultRule, name: `rule-${prev.rules.length + 1}` }] }))}
            data-testid="session-add-rule"
          >
            <IconPlus size={14} /> Add Rule
          </Button>
        </div>

        {config.rules.length === 0 ? (
          <p className="text-sm text-zinc-500">Belum ada rule. Klik Add Rule.</p>
        ) : (
          <div className="space-y-4">
            {config.rules.map((rule, idx) => (
              <div key={idx} className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 space-y-3" data-testid="session-rule-card">
                <div className="flex items-center gap-2">
                  <Input
                    value={rule.name}
                    onChange={(e) => updateRule(idx, { name: e.target.value })}
                    placeholder="rule name"
                    className="h-8 max-w-[180px] border-zinc-700 bg-zinc-900 font-mono text-sm"
                    data-testid={`session-rule-name-${idx}`}
                  />
                  <span className="ml-auto rounded-full bg-zinc-800 px-2 py-0.5 text-xs font-mono text-zinc-400">{rule.inject.to}:{rule.inject.name}</span>
                  <Button variant="outline" size="sm" onClick={() => handleTest(idx)} data-testid={`session-test-${idx}`}>
                    <IconTestPipe size={14} /> Test
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setConfig((prev) => ({ ...prev, rules: prev.rules.filter((_, i) => i !== idx) }))}>
                    <IconTrash size={14} />
                  </Button>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label className="text-zinc-300">Extract URL *</Label>
                    <Input
                      value={rule.extract_url}
                      onChange={(e) => updateRule(idx, { extract_url: e.target.value })}
                      placeholder="https://example.com/login"
                      className="border-zinc-700 bg-zinc-900 font-mono text-sm"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-zinc-300">Scope regex (optional)</Label>
                    <Input
                      value={rule.scope || ""}
                      onChange={(e) => updateRule(idx, { scope: e.target.value })}
                      placeholder=".*"
                      className="border-zinc-700 bg-zinc-900 font-mono text-sm"
                    />
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="space-y-2">
                    <Label className="text-zinc-300">From</Label>
                    <select
                      value={rule.extract.from}
                      onChange={(e) => updateExtract(idx, { from: e.target.value })}
                      className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-2 text-sm text-zinc-100"
                    >
                      <option value="body">body</option>
                      <option value="header">header</option>
                      <option value="json">json</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-zinc-300">Regex *</Label>
                    <Input
                      value={rule.extract.regex}
                      onChange={(e) => updateExtract(idx, { regex: e.target.value })}
                      placeholder='token="([^"]+)"'
                      className="border-zinc-700 bg-zinc-900 font-mono text-sm"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-zinc-300">Header / JSON path</Label>
                    <Input
                      value={rule.extract.header_name || rule.extract.json_path || ""}
                      onChange={(e) => {
                        if (rule.extract.from === "header") updateExtract(idx, { header_name: e.target.value });
                        else if (rule.extract.from === "json") updateExtract(idx, { json_path: e.target.value });
                      }}
                      placeholder={rule.extract.from === "header" ? "X-CSRF-Token" : rule.extract.from === "json" ? "data.token" : "-"}
                      className="border-zinc-700 bg-zinc-900 font-mono text-sm"
                    />
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="space-y-2">
                    <Label className="text-zinc-300">Inject To</Label>
                    <select
                      value={rule.inject.to}
                      onChange={(e) => updateInject(idx, { to: e.target.value })}
                      className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-2 text-sm text-zinc-100"
                    >
                      <option value="header">header</option>
                      <option value="cookie">cookie</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <Label className="text-zinc-300">Inject Name *</Label>
                    <Input
                      value={rule.inject.name}
                      onChange={(e) => updateInject(idx, { name: e.target.value })}
                      placeholder="X-CSRF-Token"
                      className="border-zinc-700 bg-zinc-900 font-mono text-sm"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-zinc-300">TTL seconds</Label>
                    <Input
                      type="number"
                      value={rule.ttl_seconds}
                      onChange={(e) => updateRule(idx, { ttl_seconds: Number(e.target.value) || 300 })}
                      className="border-zinc-700 bg-zinc-900 font-mono text-sm"
                    />
                  </div>
                </div>

                {testResult[idx] ? (
                  <div className={`rounded-lg border p-3 text-sm ${testResult[idx].token ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-red-500/30 bg-red-500/10 text-red-300"}`} data-testid={`session-test-result-${idx}`}>
                    {testResult[idx].token ? (
                      <span>Token: <span className="font-mono">{testResult[idx].token}</span> (status {testResult[idx].status})</span>
                    ) : (
                      <span>Error: {testResult[idx].error} status {testResult[idx].status ?? "-"}</span>
                    )}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}

        <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 space-y-3">
          <h3 className="text-sm font-semibold text-zinc-300">Reauth</h3>
          <label className="flex items-center gap-2 text-sm text-zinc-300">
            <input
              type="checkbox"
              checked={config.reauth.enabled}
              onChange={(e) => setConfig((prev) => ({ ...prev, reauth: { ...prev.reauth, enabled: e.target.checked } }))}
              className="h-4 w-4 cursor-pointer rounded border-zinc-700 bg-zinc-900 accent-sky-500"
              data-testid="session-reauth-enabled"
            />
            Enabled (retry 401/403 once)
          </label>
          {config.reauth.enabled ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-2">
                <Label className="text-zinc-300">Login URL</Label>
                <Input
                  value={config.reauth.login_url || ""}
                  onChange={(e) => setConfig((prev) => ({ ...prev, reauth: { ...prev.reauth, login_url: e.target.value } }))}
                  placeholder="https://example.com/login"
                  className="border-zinc-700 bg-zinc-900 font-mono text-sm"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-300">Login Method</Label>
                <select
                  value={config.reauth.login_method || "POST"}
                  onChange={(e) => setConfig((prev) => ({ ...prev, reauth: { ...prev.reauth, login_method: e.target.value } }))}
                  className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-2 text-sm"
                >
                  <option>POST</option><option>GET</option><option>PUT</option>
                </select>
              </div>
              <div className="space-y-2 sm:col-span-2">
                <Label className="text-zinc-300">Login Body</Label>
                <textarea
                  rows={2}
                  value={config.reauth.login_body || ""}
                  onChange={(e) => setConfig((prev) => ({ ...prev, reauth: { ...prev.reauth, login_body: e.target.value } }))}
                  placeholder="username=admin&password=secret"
                  className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm"
                />
              </div>
            </div>
          ) : null}
        </div>

        <div className="flex items-center gap-2">
          <Button onClick={handleSave} disabled={saving} data-testid="session-save">
            {saving ? "Saving..." : "Save"}
          </Button>
          {success ? <span className="flex items-center gap-1 text-sm text-emerald-300"><IconCircleCheck size={14} /> {success}</span> : null}
          {error ? <span className="flex items-center gap-1 text-sm text-red-300"><IconAlertTriangle size={14} /> {error}</span> : null}
        </div>
      </Card>
    </div>
  );
}
