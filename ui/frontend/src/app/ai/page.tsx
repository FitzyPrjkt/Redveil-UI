"use client";

import { useEffect, useState } from "react";
import { IconRobot, IconAlertTriangle, IconCircleCheck, IconRefresh } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiGet, apiPut, apiPost } from "@/lib/api";

interface Provider {
  type: string;
  protocol: string;
  base_url: string;
  model: string;
  api_key?: string;
  api_key_env?: string;
  headers?: Record<string, string>;
  timeout?: number;
}

interface AiConfig {
  enabled: boolean;
  provider?: Provider | null;
  capabilities?: { tool_calling?: boolean; vision?: boolean; structured_output?: boolean; streaming?: boolean; context_window?: number | null } | null;
  models?: Record<string, Provider> | null;
}

export default function AiPage() {
  const [config, setConfig] = useState<AiConfig>({ enabled: false, provider: null, capabilities: null, models: null });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [testPrompt, setTestPrompt] = useState("hello");
  const [testResult, setTestResult] = useState<string | null>(null);
  const [testError, setTestError] = useState<string | null>(null);
  const [capResult, setCapResult] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const data = await apiGet<AiConfig>("/api/ai/config");
        if (!cancelled) setConfig(data || { enabled: false, provider: null });
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
      const res = await apiPut<AiConfig>("/api/ai/config", config as unknown as Record<string, unknown>);
      setConfig(res);
      setSuccess("Saved");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleTest() {
    setTestResult(null);
    setTestError(null);
    try {
      const res = await apiPost<{ ok: boolean; response?: string; error?: string }>("/api/ai/test", { prompt: testPrompt });
      if (res.ok) setTestResult(res.response || "ok");
      else setTestError(res.error || "failed");
    } catch (e: unknown) {
      setTestError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleDetect() {
    setCapResult(null);
    try {
      const res = await apiPost<{ ok: boolean; capabilities?: Record<string, unknown>; error?: string }>("/api/ai/capabilities/detect", {});
      if (res.capabilities) setCapResult(JSON.stringify(res.capabilities, null, 2));
      else setCapResult(res.error || "no capabilities");
    } catch (e: unknown) {
      setCapResult(e instanceof Error ? e.message : String(e));
    }
  }

  function updateProvider(patch: Partial<Provider>) {
    setConfig((prev) => ({ ...prev, provider: { ...(prev.provider as Provider), ...patch } as Provider }));
  }

  if (loading) return <p className="text-sm text-zinc-500">Loading…</p>;

  const prov = config.provider;

  return (
    <div className="mx-auto max-w-5xl space-y-8" data-testid="ai-page">
      <header className="space-y-2">
        <h1 className="flex items-center gap-2 font-serif text-3xl font-bold tracking-tight text-zinc-100">
          <IconRobot size={24} className="text-zinc-400" />
          AI Gateway
        </h1>
        <p className="text-sm text-zinc-400">
          Provider-agnostic gateway — cek <span className="font-mono text-zinc-300">provider, model, base_url</span> & capability. Monitoring/config dedicated.
        </p>
      </header>

      <Card className="space-y-4 rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Provider</h2>
          <label className="flex items-center gap-2 text-sm text-zinc-300">
            <input type="checkbox" checked={config.enabled} onChange={(e) => setConfig((prev) => ({ ...prev, enabled: e.target.checked }))} className="h-4 w-4 rounded border-zinc-600 bg-zinc-950" data-testid="ai-enabled" />
            Enabled
          </label>
        </div>

        {!prov ? (
          <div className="space-y-3">
            <p className="text-sm text-zinc-500">No provider. Klik Add Provider.</p>
            <Button onClick={() => setConfig((prev) => ({ ...prev, provider: { type: "openai_compatible", protocol: "openai", base_url: "https://any-proxy.web.id/v1", model: "gpt-4o-mini" } as Provider }))} data-testid="ai-add-provider">
              Add Provider
            </Button>
          </div>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label className="text-zinc-300">Type</Label>
              <select value={prov.type} onChange={(e) => updateProvider({ type: e.target.value })} className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 text-sm">
                <option value="openai">openai</option>
                <option value="anthropic">anthropic</option>
                <option value="openai_compatible">openai_compatible</option>
                <option value="custom">custom</option>
              </select>
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Protocol</Label>
              <select value={prov.protocol} onChange={(e) => updateProvider({ protocol: e.target.value })} className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 text-sm">
                <option value="openai">openai</option>
                <option value="anthropic">anthropic</option>
              </select>
            </div>
            <div className="space-y-2 sm:col-span-2">
              <Label className="text-zinc-300">Base URL *</Label>
              <Input value={prov.base_url} onChange={(e) => updateProvider({ base_url: e.target.value })} placeholder="https://any-proxy.web.id/v1" className="border-zinc-700 bg-zinc-950 font-mono text-sm" data-testid="ai-base-url" />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Model *</Label>
              <Input value={prov.model} onChange={(e) => updateProvider({ model: e.target.value })} placeholder="gpt-4o-mini" className="border-zinc-700 bg-zinc-950 font-mono text-sm" />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">API Key Env</Label>
              <Input value={prov.api_key_env || ""} onChange={(e) => updateProvider({ api_key_env: e.target.value })} placeholder="ANY_PROXY_API_KEY" className="border-zinc-700 bg-zinc-950 font-mono text-sm" />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">API Key (optional)</Label>
              <Input value={prov.api_key || ""} onChange={(e) => updateProvider({ api_key: e.target.value })} placeholder="sk-..." type="password" className="border-zinc-700 bg-zinc-950 font-mono text-sm" />
              <p className="text-xs text-zinc-500">Prefer api_key_env, redacted in logs.</p>
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Timeout</Label>
              <Input type="number" value={prov.timeout ?? 30} onChange={(e) => updateProvider({ timeout: Number(e.target.value) })} className="border-zinc-700 bg-zinc-950 font-mono text-sm" />
            </div>
          </div>
        )}

        <div className="space-y-3 rounded-xl border border-zinc-800 bg-zinc-950 p-4">
          <h3 className="text-sm font-semibold text-zinc-300">Capabilities (explicit override if /v1/models not exposed)</h3>
          <div className="grid gap-3 sm:grid-cols-2">
            {[
              { key: "tool_calling", label: "Tool calling" },
              { key: "vision", label: "Vision" },
              { key: "structured_output", label: "Structured output" },
              { key: "streaming", label: "Streaming" },
            ].map((c) => (
              <label key={c.key} className="flex items-center gap-2 text-sm text-zinc-300">
                <input
                  type="checkbox"
                  checked={(config.capabilities as Record<string, boolean>)?.[c.key] ?? false}
                  onChange={(e) => setConfig((prev) => ({ ...prev, capabilities: { ...(prev.capabilities as Record<string, unknown>), [c.key]: e.target.checked } as AiConfig["capabilities"] }))}
                  className="h-4 w-4 rounded border-zinc-600 bg-zinc-950"
                  data-testid={`ai-cap-${c.key}`}
                />
                {c.label}
              </label>
            ))}
            <div className="space-y-2">
              <Label className="text-zinc-300">Context window</Label>
              <Input
                type="number"
                value={(config.capabilities as Record<string, unknown>)?.context_window as number ?? ""}
                onChange={(e) => setConfig((prev) => ({ ...prev, capabilities: { ...(prev.capabilities as Record<string, unknown>), context_window: e.target.value ? Number(e.target.value) : null } as AiConfig["capabilities"] }))}
                placeholder="128000"
                className="border-zinc-700 bg-zinc-900 font-mono text-sm"
              />
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={handleSave} disabled={saving} data-testid="ai-save">
            {saving ? "Saving..." : "Save"}
          </Button>
          <Button variant="outline" onClick={handleDetect} data-testid="ai-detect">
            <IconRefresh size={14} /> Detect Capabilities
          </Button>
          {success ? <span className="flex items-center gap-1 text-sm text-emerald-300"><IconCircleCheck size={14} /> {success}</span> : null}
          {error ? <span className="flex items-center gap-1 text-sm text-red-300"><IconAlertTriangle size={14} /> {error}</span> : null}
        </div>
        {capResult ? <pre className="overflow-auto rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-xs text-zinc-300" data-testid="ai-cap-result">{capResult}</pre> : null}
      </Card>

      <Card className="space-y-3 rounded-xl border border-zinc-800 bg-zinc-900 p-5" data-testid="ai-test">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Test Connection</h2>
        <div className="flex gap-2">
          <Input value={testPrompt} onChange={(e) => setTestPrompt(e.target.value)} placeholder="hello" className="flex-1 border-zinc-700 bg-zinc-950 font-mono text-sm" data-testid="ai-test-prompt" />
          <Button onClick={handleTest} variant="outline" data-testid="ai-test-btn">Test</Button>
        </div>
        {testResult ? <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 font-mono text-sm text-emerald-300" data-testid="ai-test-ok">{testResult}</div> : null}
        {testError ? <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300" data-testid="ai-test-error">{testError}</div> : null}
      </Card>
    </div>
  );
}
