"use client";

import { useEffect, useMemo, useState } from "react";
import {
  IconAlertTriangle,
  IconArrowRight,
  IconBomb,
  IconCheck,
  IconCopy,
  IconGitFork,
  IconHistory,
  IconLock,
  IconShieldLock,
  IconTarget,
  IconWaveSine,
  IconX,
} from "@tabler/icons-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge as UiBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { apiGet, apiPost } from "@/lib/api";
import { cn } from "@/lib/utils";

type Mode = "preset" | "custom";
type Method = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";

interface PayloadSet {
  check_id: string;
  label: string;
  kind: "delay" | "canary";
  payload_count: number;
}

interface ProbeSample {
  index: number;
  payload: string;
  status_code: number;
  elapsed_ms: number;
  body_length: number;
  body_excerpt: string;
  error: string | null;
  method: string;
  target_url: string;
  position: string;
  started_at: string;
}

interface ProbeRunResult {
  probe_id: string;
  target_id: number;
  scan_id: number;
  finding_wpoc_id: string;
  mode: Mode;
  method: Method;
  target_url: string;
  total_requested: number;
  total_executed: number;
  skipped: number;
  scope_rejections: number;
  samples: ProbeSample[];
  started_at: string;
  completed_at: string;
}

interface Target {
  id: number;
  url: string;
  name: string | null;
}

const DWYOR_REQUIRED_TEXT = "I ACKNOWLEDGE DWYOR";

const METHODS: Method[] = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
];

export default function ProbeBuilderPage() {
  // --- core state ---------------------------------------------------------
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [payloadSets, setPayloadSets] = useState<PayloadSet[] | null>(null);
  const [mode, setMode] = useState<Mode>("preset");
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null);
  const [method, setMethod] = useState<Method>("GET");
  const [position, setPosition] = useState<string>("q");
  const [positionKind, setPositionKind] = useState<"query" | "path" | "body">(
    "query",
  );
  const [pathTemplate, setPathTemplate] = useState<string>("");
  const [bodyTemplate, setBodyTemplate] = useState<string>("");
  // B2: attack mode + processors
  const [attackMode, setAttackMode] = useState<"sniper" | "battering_ram" | "pitchfork" | "cluster_bomb">("sniper");
  const [payloadProcessors, setPayloadProcessors] = useState<string[]>([]);
  const [processorInput, setProcessorInput] = useState<string>("url_encode");
  const [prefixInput, setPrefixInput] = useState<string>("");
  const [suffixInput, setSuffixInput] = useState<string>("");
  const [payloads2, setPayloads2] = useState<string>("");
  const [position2, setPosition2] = useState<string>("");
  // preset mode
  const [presetCheckId, setPresetCheckId] = useState<string>("");
  const [presetPayloadIndices, setPresetPayloadIndices] = useState<string>(
    "0,1,2",
  );
  // custom mode
  const [customPayloads, setCustomPayloads] = useState<string>("");
  // gates
  const [gate1Open, setGate1Open] = useState(false);
  const [gate2Text, setGate2Text] = useState("");
  // result
  const [result, setResult] = useState<ProbeRunResult | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  // result sorting
  const [sortBy, setSortBy] = useState<"index" | "status" | "length" | "time">(
    "index",
  );

  // --- load dependencies --------------------------------------------------
  useEffect(() => {
    apiGet<Target[]>("/api/targets")
      .then((t) => {
        setTargets(t);
        if (t.length && selectedTargetId === null) setSelectedTargetId(t[0].id);
      })
      .catch((err: unknown) => setSubmitError(String(err)));
    apiGet<PayloadSet[]>("/api/probes/payload-sets")
      .then((p) => {
        setPayloadSets(p);
        if (p.length && !presetCheckId) setPresetCheckId(p[0].check_id);
      })
      .catch(() => {
        /* non-fatal — UI falls back to custom mode */
      });
    // Prefill from query ?endpoint=&method= (from Scan detail Probe CTA)
    try {
      const sp = new URLSearchParams(typeof window !== "undefined" ? window.location.search : "");
      const ep = sp.get("endpoint");
      const m = sp.get("method");
      if (ep) {
        if (ep.includes("?") || ep.includes("{")) {
          setPositionKind("query");
          const q = ep.split("?")[1] || "";
          const param = q.split("=")[0] || q.split("&")[0] || "q";
          setPosition(param || "q");
          setPathTemplate(ep);
        } else {
          setPositionKind("path");
          setPathTemplate(ep.includes("{payload}") ? ep : `${ep}`);
          setPosition(ep);
        }
      }
      if (m && ["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"].includes(m.toUpperCase())) {
        setMethod(m.toUpperCase() as Method);
      }
    } catch {}
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectedTarget = useMemo(
    () => targets?.find((t) => t.id === selectedTargetId) ?? null,
    [targets, selectedTargetId],
  );

  // --- derived: payload list to send ------------------------------------
  const presetPayloadList = useMemo(() => {
    if (mode !== "preset") return [];
    return presetPayloadIndices
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }, [mode, presetPayloadIndices]);

  const customPayloadList = useMemo(() => {
    if (mode !== "custom") return [];
    return customPayloads
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }, [mode, customPayloads]);

  const payloads2List = useMemo(() => payloads2.split("\n").map((s) => s.trim()).filter(Boolean), [payloads2]);
  const baseCount = mode === "preset" ? presetPayloadList.length : customPayloadList.length;
  const payloadCount = (() => {
    if (attackMode === "pitchfork") {
      if (payloads2List.length === 0) return baseCount;
      return Math.min(baseCount, payloads2List.length);
    }
    if (attackMode === "cluster_bomb") {
      if (payloads2List.length === 0) return baseCount;
      return baseCount * payloads2List.length;
    }
    return baseCount;
  })();
  const rps = 2.0; // matches LimitsConfig default
  const estDurationSec = payloadCount > 0 ? Math.ceil(payloadCount / rps) : 0;
  const canSubmit =
    selectedTargetId !== null &&
    payloadCount > 0 &&
    gate1Open &&
    gate2Text === DWYOR_REQUIRED_TEXT;

  // --- actions -----------------------------------------------------------
  function openGate1() {
    if (payloadCount === 0) {
      setSubmitError("Add at least one payload before continuing.");
      return;
    }
    if (!selectedTargetId) {
      setSubmitError("Select a target.");
      return;
    }
    setSubmitError(null);
    setGate1Open(true);
  }

  async function runProbe() {
    if (!canSubmit || !selectedTarget) return;
    setSubmitting(true);
    setSubmitError(null);
    setResult(null);
    try {
      const body: Record<string, unknown> = {
        target_id: selectedTarget.id,
        method,
        position: position || "q",
        position_kind: positionKind,
        path_template: positionKind === "path" ? pathTemplate : null,
        body_template: positionKind === "body" ? bodyTemplate : null,
        confirmed_dwyor: true,
        attack_mode: attackMode,
        preset_check_id: mode === "preset" ? presetCheckId : null,
        payloads: mode === "preset" ? presetPayloadList : customPayloadList,
        payload_processors: payloadProcessors.length ? payloadProcessors : null,
      };
      if (attackMode === "pitchfork" || attackMode === "cluster_bomb" || attackMode === "battering_ram") {
        if (position2) body.position2 = position2;
        if (payloads2List.length) body.payloads2 = payloads2List;
      }
      const data = await apiPost<ProbeRunResult>("/api/probes/custom", body);
      setResult(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setSubmitError(message);
    } finally {
      setSubmitting(false);
    }
  }

  function resetGates() {
    setGate1Open(false);
    setGate2Text("");
  }

  // --- derived: sorted samples -------------------------------------------
  const sortedSamples = useMemo(() => {
    if (!result) return [];
    const arr = [...result.samples];
    arr.sort((a, b) => {
      switch (sortBy) {
        case "index":
          return a.index - b.index;
        case "status":
          return a.status_code - b.status_code;
        case "length":
          return a.body_length - b.body_length;
        case "time":
          return a.elapsed_ms - b.elapsed_ms;
      }
    });
    return arr;
  }, [result, sortBy]);

  return (
    <div className="space-y-8" data-testid="probe-builder">
      <header className="space-y-2">
        <div className="flex items-center gap-3">
          <IconWaveSine
            size={32}
            className="shrink-0 text-zinc-500"
            aria-hidden="true"
          />
          <h1 className="font-sans text-3xl font-semibold tracking-tight text-zinc-100">
            Probe Builder
          </h1>
        </div>
        <p className="text-sm text-zinc-400">
          Operator-driven payload probing. Preset mode uses curated
          payloads from registered checks; Custom mode requires an
          explicit DWYOR acknowledgement.
        </p>
      </header>

      {/* ---- 1. Mode toggle ---- */}
      <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <div
          role="tablist"
          aria-label="Mode"
          className="flex gap-2"
        >
          <button
            role="tab"
            aria-selected={mode === "preset"}
            data-testid="mode-preset"
            onClick={() => {
              setMode("preset");
              resetGates();
            }}
            className={cn(
              "rounded-lg px-4 py-2 text-sm font-medium transition-colors",
              mode === "preset"
                ? "bg-zinc-700 text-zinc-100"
                : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700",
            )}
          >
            Preset (curated from registered checks)
          </button>
          <button
            role="tab"
            aria-selected={mode === "custom"}
            data-testid="mode-custom"
            onClick={() => {
              setMode("custom");
              resetGates();
            }}
            className={cn(
              "rounded-lg px-4 py-2 text-sm font-medium transition-colors",
              mode === "custom"
                ? "bg-zinc-700 text-zinc-100"
                : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700",
            )}
          >
            Custom payload
          </button>
        </div>
      </Card>

      {/* ---- 2. Mode-specific config ---- */}
      <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
        <CardHeader className="pb-3">
          <CardTitle className="text-xs font-medium uppercase tracking-wider text-zinc-400">
            Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Target */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              Target
            </label>
            {targets === null ? (
              <Skeleton className="h-8 w-full" />
            ) : targets.length === 0 ? (
              <div data-testid="empty-targets" className="rounded-xl border border-zinc-800 bg-zinc-900 p-8 text-center">
                <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-full bg-zinc-800">
                  <IconTarget size={20} className="text-zinc-500" aria-hidden="true" />
                </div>
                <h3 className="mt-3 font-sans text-sm font-medium text-zinc-300">No targets yet</h3>
                <p className="mt-1 text-xs text-zinc-500">Create a target to start probing. You can also import from OpenAPI.</p>
                <div className="mt-4 flex justify-center gap-2">
                  <a href="/targets/new" data-testid="empty-create-target" className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-4 py-2 text-sm font-medium text-white hover:bg-sky-600">
                    Create target
                  </a>
                  <a href="/targets" className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-950 px-4 py-2 text-sm text-zinc-300 hover:bg-zinc-800">Learn about Probe Builder</a>
                </div>
              </div>
            ) : (
              <select
                data-testid="target-select"
                value={selectedTargetId ?? ""}
                onChange={(e) => {
                  setSelectedTargetId(Number(e.target.value));
                  resetGates();
                }}
                className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 text-sm text-zinc-100"
              >
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name ? `${t.name} (${t.url})` : t.url}
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Method */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">
                Method
              </label>
              <select
                data-testid="method-select"
                value={method}
                onChange={(e) => setMethod(e.target.value as Method)}
                className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 text-sm text-zinc-100"
              >
                {METHODS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">
                Position kind
              </label>
              <select
                data-testid="position-kind-select"
                value={positionKind}
                onChange={(e) =>
                  setPositionKind(e.target.value as "query" | "path" | "body")
                }
                className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 text-sm text-zinc-100"
              >
                <option value="query">Query parameter (?p=)</option>
                <option value="path">{"Path segment (/users/{payload})"}</option>
                <option value="body">Body payload</option>
              </select>
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">
              {positionKind === "path" ? "Path template" : "Parameter name"}
            </label>
            {positionKind === "path" ? (
              <input
                data-testid="path-template"
                type="text"
                value={pathTemplate}
                onChange={(e) => setPathTemplate(e.target.value)}
                placeholder="/api/users/{payload}"
                className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500"
              />
            ) : positionKind === "body" ? (
              <textarea
                data-testid="body-template"
                rows={4}
                value={bodyTemplate}
                onChange={(e) => setBodyTemplate(e.target.value)}
                placeholder={'{"id": "{payload}"}'}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-sm text-zinc-100 placeholder:text-zinc-500"
              />
            ) : (
              <input
                data-testid="position-input"
                type="text"
                value={position}
                onChange={(e) => setPosition(e.target.value)}
                placeholder="q"
                className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500"
              />
            )}
          </div>

          {/* Position Preview — Item 2 */}
          <div data-testid="position-preview" className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
            <div className="text-xs font-medium uppercase tracking-wider text-zinc-500">Preview</div>
            {(() => {
              const base = selectedTarget?.url?.replace(/\/$/, "") ?? "https://target.example.com";
              const payloadHl = <span className="rounded border border-sky-500/30 bg-sky-500/20 px-1 font-mono text-sky-300">[PAYLOAD]</span>;
              if (positionKind === "body") {
                const tmpl = bodyTemplate || '{"id": "{payload}"}';
                const parts = tmpl.split("{payload}");
                return (
                  <div className="mt-2 space-y-1">
                    <div className="font-mono text-xs text-zinc-200">{method} {base} <span className="text-zinc-500">(body)</span></div>
                    <pre className="overflow-x-auto rounded-md bg-zinc-950 p-2 font-mono text-xs text-zinc-300">{parts[0]}<span className="rounded border border-sky-500/30 bg-sky-500/20 px-1 text-sky-300">PAYLOAD</span>{parts[1] ?? ""}</pre>
                    <div className="font-mono text-xs text-zinc-500">2 rps · ScopeController ✓</div>
                  </div>
                );
              }
              if (positionKind === "path") {
                const tmpl = pathTemplate || "/api/users/{payload}";
                const url = `${base}${tmpl.startsWith("/") ? tmpl : `/${tmpl}`}`;
                const preview = url.replace("{payload}", "§PAYLOAD§");
                const [pre, post] = preview.split("§PAYLOAD§");
                return (
                  <div className="mt-2 space-y-1">
                    <div className="font-mono text-xs text-zinc-200">{method} <span className="text-zinc-400">{pre}</span>{payloadHl}<span className="text-zinc-400">{post}</span></div>
                    <div className="font-mono text-xs text-zinc-500">2 rps · ScopeController ✓</div>
                  </div>
                );
              }
              // query
              const param = position || "q";
              return (
                <div className="mt-2 space-y-1">
                  <div className="font-mono text-xs text-zinc-200">{method} {base}?<span className="text-zinc-400">{param}=</span>{payloadHl}</div>
                  <div className="font-mono text-xs text-zinc-500">2 rps · ScopeController ✓</div>
                </div>
              );
            })()}
          </div>

          {/* Attack Mode — B2 */}
          <div className="space-y-3 rounded-lg border border-zinc-800 bg-zinc-950 p-4" data-testid="attack-mode-section">
            <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">Attack Mode</label>
            <div role="tablist" className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {[
                { id: "sniper", label: "Sniper", Icon: IconTarget, desc: "1 payload, 1 posisi bergiliran" },
                { id: "battering_ram", label: "Battering Ram", Icon: IconCopy, desc: "1 payload, N posisi bersamaan" },
                { id: "pitchfork", label: "Pitchfork", Icon: IconGitFork, desc: "2 list paralel, paired" },
                { id: "cluster_bomb", label: "Cluster Bomb", Icon: IconBomb, desc: "cartesian product" },
              ].map((m) => {
                const active = attackMode === m.id;
                const Ico = m.Icon;
                return (
                  <button
                    key={m.id}
                    role="tab"
                    aria-selected={active}
                    data-testid={`attack-mode-${m.id}`}
                    onClick={() => setAttackMode(m.id as typeof attackMode)}
                    className={`flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition-colors ${active ? "border-sky-500/50 bg-sky-500/10 text-sky-200" : "border-zinc-700 bg-zinc-900 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200"}`}
                  >
                    <span className="flex items-center gap-1.5 text-xs font-semibold"><Ico size={14} aria-hidden="true" />{m.label}</span>
                    <span className="font-mono text-xs leading-tight text-zinc-500">{m.desc}</span>
                  </button>
                );
              })}
            </div>
            <p className="font-mono text-xs text-zinc-400" data-testid="attack-mode-desc">
              {attackMode === "sniper" ? "Sniper — 1 payload, 1 posisi bergiliran (q=PAYLOAD)" : attackMode === "battering_ram" ? "Battering Ram — 1 payload ke N posisi bersamaan (q & id = same)" : attackMode === "pitchfork" ? "Pitchfork — 2 list paralel, row-by-row (user[0]:pass[0])" : "Cluster Bomb — cartesian product (user × pass = 9 req jika 3×3)"}
            </p>
            {(attackMode === "battering_ram" || attackMode === "pitchfork" || attackMode === "cluster_bomb") ? (
              <div className="space-y-1.5">
                <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">Position 2 {attackMode === "battering_ram" ? "(same payload)" : ""}</label>
                <input data-testid="position2-input" type="text" value={position2} onChange={(e) => setPosition2(e.target.value)} placeholder={attackMode === "battering_ram" ? "id (same payload)" : "id"} className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500" />
              </div>
            ) : null}
          </div>

          {/* Payload source */}
          {mode === "preset" ? (
            <PresetPayloadForm
              sets={payloadSets ?? []}
              selectedCheckId={presetCheckId}
              onSelectCheck={setPresetCheckId}
              indicesText={presetPayloadIndices}
              onChangeIndices={setPresetPayloadIndices}
            />
          ) : (
            <CustomPayloadForm
              value={customPayloads}
              onChange={setCustomPayloads}
              count={customPayloadList.length}
            />
          )}
          {(attackMode === "pitchfork" || attackMode === "cluster_bomb") ? (
            <div className="space-y-1.5 rounded-lg border border-zinc-800 bg-zinc-950 p-4" data-testid="payloads2-section">
              <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">Payloads 2 — list kedua ({attackMode === "pitchfork" ? "paired" : "cartesian"})</label>
              <textarea data-testid="payloads2-input" rows={3} value={payloads2} onChange={(e) => setPayloads2(e.target.value)} placeholder={"admin\ntest\npayload for second position"} className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500" />
              <p className="font-mono text-xs text-zinc-500">{payloads2.split("\n").filter(Boolean).length} payloads{attackMode === "cluster_bomb" && customPayloadList.length ? ` × ${customPayloadList.length} = ${customPayloadList.length * payloads2.split("\n").filter(Boolean).length} requests` : attackMode === "pitchfork" ? ` → ${Math.min(customPayloadList.length, payloads2.split("\n").filter(Boolean).length)} requests (paired)` : ""}</p>
            </div>
          ) : null}

          {/* Payload Processors — B2 */}
          <div className="space-y-3 rounded-lg border border-zinc-800 bg-zinc-950 p-4" data-testid="processors-section">
            <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">Payload Processors</label>
            <div className="flex flex-wrap items-center gap-2">
              <select data-testid="processor-select" value={processorInput} onChange={(e) => setProcessorInput(e.target.value)} className="h-8 rounded-lg border border-zinc-700 bg-zinc-900 px-2 text-sm text-zinc-100">
                <option value="url_encode">url_encode</option>
                <option value="base64">base64</option>
                <option value="hex">hex</option>
                <option value="html_encode">html_encode</option>
                <option value="upper">upper</option>
                <option value="lower">lower</option>
                <option value="prefix:">prefix:</option>
                <option value="suffix:">suffix:</option>
              </select>
              {(processorInput === "prefix:" || processorInput === "suffix:") ? (
                <>
                  <input data-testid="processor-prefix-input" type="text" value={processorInput.startsWith("prefix:") ? prefixInput : suffixInput} onChange={(e) => processorInput.startsWith("prefix:") ? setPrefixInput(e.target.value) : setSuffixInput(e.target.value)} placeholder={processorInput.startsWith("prefix:") ? "prefix value" : "suffix value"} className="h-8 w-24 rounded-lg border border-zinc-700 bg-zinc-900 px-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500" />
                  <Button data-testid="processor-add" size="sm" variant="outline" onClick={() => {
                    const val = processorInput.startsWith("prefix:") ? `prefix:${prefixInput}` : `suffix:${suffixInput}`;
                    if (!val.split(":")[1]) return;
                    setPayloadProcessors([...payloadProcessors, val]);
                    setPrefixInput(""); setSuffixInput("");
                  }}>Add</Button>
                </>
              ) : (
                <Button data-testid="processor-add" size="sm" variant="outline" onClick={() => { if (!payloadProcessors.includes(processorInput)) setPayloadProcessors([...payloadProcessors, processorInput]); }}>Add</Button>
              )}
            </div>
            {payloadProcessors.length > 0 ? (
              <div className="flex flex-wrap gap-2" data-testid="processor-chips">
                {payloadProcessors.map((proc, idx) => (
                  <span key={`${proc}-${idx}`} data-testid="processor-chip" className="inline-flex items-center gap-1 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono text-xs text-zinc-300">
                    {proc}
                    <button data-testid={`processor-remove-${idx}`} onClick={() => setPayloadProcessors(payloadProcessors.filter((_, i) => i !== idx))} className="ml-1 text-zinc-500 hover:text-zinc-200">×</button>
                    <span className="ml-1 flex gap-0.5">
                      <button data-testid={`processor-up-${idx}`} disabled={idx===0} onClick={() => { const a=[...payloadProcessors]; [a[idx-1],a[idx]]=[a[idx],a[idx-1]]; setPayloadProcessors(a); }} className="px-1 text-zinc-500 hover:text-zinc-200 disabled:opacity-30">↑</button>
                      <button data-testid={`processor-down-${idx}`} disabled={idx===payloadProcessors.length-1} onClick={() => { const a=[...payloadProcessors]; [a[idx],a[idx+1]]=[a[idx+1],a[idx]]; setPayloadProcessors(a); }} className="px-1 text-zinc-500 hover:text-zinc-200 disabled:opacity-30">↓</button>
                    </span>
                  </span>
                ))}
              </div>
            ) : (
              <p className="font-mono text-xs text-zinc-500">No processors — payload dikirim apa adanya.</p>
            )}
            {(() => {
              const sample = mode === "preset" ? "test' OR 1=1" : (customPayloadList[0] || "test' OR 1=1");
              let out = sample;
              for (const p of payloadProcessors) {
                const proc = p.toLowerCase();
                if (proc === "url_encode") out = encodeURIComponent(out);
                else if (proc === "base64") try { out = btoa(out); } catch {}
                else if (proc === "hex") out = [...out].map(c => c.charCodeAt(0).toString(16).padStart(2,"0")).join("");
                else if (proc === "html_encode") out = out.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
                else if (proc.startsWith("prefix:")) out = p.slice(7) + out;
                else if (proc.startsWith("suffix:")) out = out + p.slice(7);
                else if (proc === "upper") out = out.toUpperCase();
                else if (proc === "lower") out = out.toLowerCase();
              }
              return <div data-testid="processor-preview" className="rounded-md bg-zinc-900 p-2 font-mono text-xs"><span className="text-zinc-500">preview:</span> <span className="text-sky-300">{sample}</span> <span className="text-zinc-500">→</span> <span className="text-emerald-300">{out}</span></div>;
            })()}
          </div>
        </CardContent>
      </Card>

      {/* ---- 3. Gate 1: summary ---- */}
      <Gate1Summary
        open={gate1Open}
        onRequestOpen={openGate1}
        onCancel={resetGates}
        target={selectedTarget}
        mode={mode}
        method={method}
        position={position}
        payloadCount={payloadCount}
        estDurationSec={estDurationSec}
      />

      {/* ---- 4. Gate 2: DWYOR ---- */}
      {gate1Open ? (
        <Gate2Dwyor
          value={gate2Text}
          onChange={setGate2Text}
          required={DWYOR_REQUIRED_TEXT}
        />
      ) : null}

      {/* ---- 5. Run + errors ---- */}
      {gate2Text === DWYOR_REQUIRED_TEXT ? (
        <div className="flex items-center gap-3">
          <Button
            data-testid="run-probe"
            onClick={runProbe}
            disabled={!canSubmit || submitting}
            className="gap-1.5"
          >
            <IconShieldLock size={14} aria-hidden="true" />
            {submitting ? "Running probe…" : `Run probe (${payloadCount} payload${payloadCount === 1 ? "" : "s"})`}
          </Button>
          {submitError ? (
            <div
              role="alert"
              className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300"
            >
              {submitError}
            </div>
          ) : null}
        </div>
      ) : null}

      {/* ---- 6. Results table ---- */}
      {result ? (
        <ProbeResults
          result={result}
          sortBy={sortBy}
          onChangeSort={setSortBy}
          sortedSamples={sortedSamples}
        />
      ) : null}
    </div>
  );
}

// --- subcomponents -------------------------------------------------------

function PresetPayloadForm({
  sets,
  selectedCheckId,
  onSelectCheck,
  indicesText,
  onChangeIndices,
}: {
  sets: PayloadSet[];
  selectedCheckId: string;
  onSelectCheck: (id: string) => void;
  indicesText: string;
  onChangeIndices: (s: string) => void;
}) {
  return (
    <div className="space-y-3 rounded-lg border border-zinc-800 bg-zinc-950 p-4">
      <div className="space-y-1.5">
        <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">
          Payload set
        </label>
        {sets.length === 0 ? (
          <p className="text-xs text-zinc-500">No preset payload sets registered.</p>
        ) : (
          <select
            data-testid="preset-set-select"
            value={selectedCheckId}
            onChange={(e) => onSelectCheck(e.target.value)}
            className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-2 text-sm text-zinc-100"
          >
            {sets.map((s) => (
              <option key={s.check_id} value={s.check_id}>
                {s.label} ({s.payload_count} payloads)
              </option>
            ))}
          </select>
        )}
      </div>
      <div className="space-y-1.5">
        <label className="text-xs font-medium uppercase tracking-wider text-zinc-400">
          Payload indices (comma- or space-separated, 0-based)
        </label>
        <input
          data-testid="preset-indices-input"
          type="text"
          value={indicesText}
          onChange={(e) => onChangeIndices(e.target.value)}
          placeholder="0,1,2"
          className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-900 px-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500"
        />
      </div>
    </div>
  );
}

function CustomPayloadForm({
  value,
  onChange,
  count,
}: {
  value: string;
  onChange: (s: string) => void;
  count: number;
}) {
  return (
    <div className="space-y-1.5 rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-4">
      <div className="flex items-center gap-2">
        <IconAlertTriangle
          size={14}
          className="text-yellow-400"
          aria-hidden="true"
        />
        <label className="text-xs font-medium uppercase tracking-wider text-yellow-300">
          Custom payloads (one per line)
        </label>
        <span className="ml-auto font-mono text-[10px] text-yellow-400">
          {count} payload{count === 1 ? "" : "s"}
        </span>
      </div>
      <textarea
        data-testid="custom-payloads-input"
        rows={6}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={"1' AND SLEEP(5)-- -\nadmin' --\n../../etc/passwd"}
        className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-yellow-500/50 focus:outline-none"
      />
      <p className="text-xs text-yellow-300/80">
        Custom payloads are NOT curated by Redveil. They run only after you
        type the DWYOR acknowledgement in the gate below.
      </p>
    </div>
  );
}

function Gate1Summary({
  open,
  onRequestOpen,
  onCancel,
  target,
  mode,
  method,
  position,
  payloadCount,
  estDurationSec,
}: {
  open: boolean;
  onRequestOpen: () => void;
  onCancel: () => void;
  target: Target | null;
  mode: Mode;
  method: Method;
  position: string;
  payloadCount: number;
  estDurationSec: number;
}) {
  if (!open) {
    return (
      <div className="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <p className="text-sm text-zinc-400">
          Ready to run {payloadCount} payload{payloadCount === 1 ? "" : "s"}.
          Review and continue.
        </p>
        <Button
          data-testid="open-gate1"
          onClick={onRequestOpen}
          disabled={payloadCount === 0}
          className="gap-1.5"
        >
          Continue
          <IconArrowRight size={14} aria-hidden="true" />
        </Button>
      </div>
    );
  }
  return (
    <div
      data-testid="gate1"
      className="space-y-3 rounded-xl border border-zinc-800 bg-zinc-900 p-5"
    >
      <div className="flex items-center gap-2">
        <IconShieldLock
          size={18}
          className="text-zinc-500"
          aria-hidden="true"
        />
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-200">
          Gate 1 — confirm
        </h2>
      </div>
      <ul className="space-y-1.5 text-sm">
        <li className="flex items-center justify-between">
          <span className="text-zinc-400">Target</span>
          <span className="font-mono text-zinc-200">
            {target ? target.url : "—"}
          </span>
        </li>
        <li className="flex items-center justify-between">
          <span className="text-zinc-400">Method</span>
          <span className="font-mono text-zinc-200">{method}</span>
        </li>
        <li className="flex items-center justify-between">
          <span className="text-zinc-400">Position</span>
          <span className="font-mono text-zinc-200">
            {position || "—"}
          </span>
        </li>
        <li className="flex items-center justify-between">
          <span className="text-zinc-400">Mode</span>
          <UiBadge
            variant="outline"
            className={cn(
              "border",
              mode === "custom"
                ? "bg-yellow-500/15 text-yellow-300 border-yellow-500/30"
                : "bg-zinc-800 text-zinc-200 border-zinc-700",
            )}
          >
            {mode}
          </UiBadge>
        </li>
        <li className="flex items-center justify-between">
          <span className="text-zinc-400">Total requests</span>
          <span className="font-mono text-zinc-200">
            {payloadCount} payload{payloadCount === 1 ? "" : "s"} × 1 position = {payloadCount} request{payloadCount === 1 ? "" : "s"}
          </span>
        </li>
        <li className="flex items-center justify-between">
          <span className="text-zinc-400">Estimated duration</span>
          <span className="font-mono text-zinc-200">
            ~{estDurationSec}s (2 rps, includes ScopeController gate)
          </span>
        </li>
      </ul>
      <div className="flex items-center justify-end gap-2 pt-2">
        <Button
          data-testid="gate1-cancel"
          variant="outline"
          onClick={onCancel}
        >
          Cancel
        </Button>
        <Button
          data-testid="gate1-continue"
          onClick={onRequestOpen}
          className="gap-1.5"
        >
          Continue to DWYOR
          <IconArrowRight size={14} aria-hidden="true" />
        </Button>
      </div>
    </div>
  );
}

function Gate2Dwyor({
  value,
  onChange,
  required,
}: {
  value: string;
  onChange: (s: string) => void;
  required: string;
}) {
  const matches = value === required;
  return (
    <div
      data-testid="gate2"
      className={cn(
        "rounded-xl border bg-zinc-900 p-5",
        matches ? "border-emerald-500/30" : "border-yellow-500/30",
      )}
    >
      <div className="flex items-center gap-2">
        <IconLock size={18} className="text-yellow-400" aria-hidden="true" />
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-200">
          Gate 2 — DWYOR acknowledgement
        </h2>
      </div>
      <p className="mt-3 text-sm text-zinc-300">
        Custom payloads are NOT curated by Redveil. The endpoint will refuse
        this request unless the body sets <code className="font-mono">confirmed_dwyor: true</code>.
        Type the phrase below exactly to enable the Run button.
      </p>
      <blockquote className="mt-3 rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-sm text-zinc-400">
        <strong className="text-zinc-200">DWYOR — Do With Your Own Risk.</strong>{" "}
        Authorized testing only. The operator bears full responsibility for
        custom payload content. Unlike Preset mode, these payloads do not
        pass through Redveil's safety curation. Ensure you have explicit
        permission to probe the target.
      </blockquote>
      <label className="mt-4 block text-xs font-medium uppercase tracking-wider text-zinc-400">
        Type the phrase below EXACTLY to unlock the Run button
      </label>
      <div className="mt-1 flex items-center gap-2">
        <code className="rounded-md border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-xs text-zinc-300">
          {required}
        </code>
      </div>
      <input
        data-testid="gate2-input"
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Type the phrase above to enable Run"
        className="mt-2 h-9 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 font-mono text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-yellow-500/50 focus:outline-none"
        autoComplete="off"
        spellCheck={false}
      />
      {matches ? (
        <div className="mt-2 flex items-center gap-2 text-xs text-emerald-400">
          <IconCheck size={12} aria-hidden="true" />
          Acknowledged. Run button unlocked.
        </div>
      ) : value.length > 0 ? (
        <div className="mt-2 flex items-center gap-2 text-xs text-yellow-400">
          <IconX size={12} aria-hidden="true" />
          Phrase does not match. Type it exactly to continue.
        </div>
      ) : null}
    </div>
  );
}

function ProbeResults({
  result,
  sortBy,
  onChangeSort,
  sortedSamples,
}: {
  result: ProbeRunResult;
  sortBy: "index" | "status" | "length" | "time";
  onChangeSort: (s: "index" | "status" | "length" | "time") => void;
  sortedSamples: ProbeSample[];
}) {
  function statusClass(s: number): string {
    if (s >= 200 && s < 300) return "text-emerald-400";
    if (s >= 300 && s < 400) return "text-sky-400";
    if (s >= 400 && s < 500) return "text-yellow-400";
    if (s >= 500) return "text-red-400";
    return "text-zinc-500";
  }
  return (
    <Card className="rounded-xl border border-zinc-800 bg-zinc-900">
      <CardHeader className="border-b border-zinc-800 pb-3">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <CardTitle className="text-sm font-semibold uppercase tracking-wider text-zinc-200">
              Results
            </CardTitle>
            <p className="text-xs text-zinc-500">
              probe_id {result.probe_id} · finding {result.finding_wpoc_id} ·
              scan {result.scan_id}
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <UiBadge variant="outline" className="border-zinc-700 bg-zinc-800 text-zinc-300">
              {result.mode}
            </UiBadge>
            <UiBadge variant="outline" className="border-zinc-700 bg-zinc-800 text-zinc-300">
              {result.total_executed}/{result.total_requested} executed
            </UiBadge>
            {result.scope_rejections > 0 ? (
              <UiBadge
                variant="outline"
                className="border-red-500/30 bg-red-500/10 text-red-300"
              >
                {result.scope_rejections} scope-rejected
              </UiBadge>
            ) : null}
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="mb-3 flex items-center gap-2 text-xs">
          <span className="text-zinc-500">Sort by</span>
          {(["index", "status", "length", "time"] as const).map((k) => (
            <button
              key={k}
              onClick={() => onChangeSort(k)}
              data-testid={`sort-${k}`}
              className={cn(
                "rounded-md px-2 py-0.5",
                sortBy === k
                  ? "bg-zinc-700 text-zinc-100"
                  : "text-zinc-400 hover:bg-zinc-800",
              )}
            >
              {k}
            </button>
          ))}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="border-b border-zinc-800 text-zinc-400">
              <tr>
                <th className="px-2 py-2 text-left font-medium">#</th>
                <th className="px-2 py-2 text-left font-medium">Payload</th>
                <th className="px-2 py-2 text-left font-medium">Status</th>
                <th className="px-2 py-2 text-right font-medium">Length</th>
                <th className="px-2 py-2 text-right font-medium">Time (ms)</th>
                <th className="px-2 py-2 text-left font-medium">Notes</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {sortedSamples.map((s) => (
                <tr
                  key={s.index}
                  className="border-b border-zinc-800/50 hover:bg-zinc-800/30"
                >
                  <td className="px-2 py-2 text-zinc-500">{s.index}</td>
                  <td className="max-w-md truncate px-2 py-2 text-zinc-200">
                    {s.payload}
                  </td>
                  <td className={cn("px-2 py-2", statusClass(s.status_code))}>
                    {s.error ? "—" : s.status_code}
                  </td>
                  <td className="px-2 py-2 text-right text-zinc-300">
                    {s.body_length}
                  </td>
                  <td className="px-2 py-2 text-right text-zinc-300">
                    {s.elapsed_ms ? s.elapsed_ms.toFixed(1) : "—"}
                  </td>
                  <td className="px-2 py-2 text-zinc-500">
                    {s.error ?? s.body_excerpt.slice(0, 60)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {result.scope_rejections > 0 ? (
          <div
            role="alert"
            className="mt-4 flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-xs text-yellow-300"
          >
            <IconAlertTriangle size={12} className="mt-0.5 shrink-0" aria-hidden="true" />
            <span>
              {result.scope_rejections} payload{result.scope_rejections === 1 ? " was" : "s were"} rejected by
              ScopeController before reaching the network. Check the
              target's scope configuration (allowed_hosts / allowed_paths)
              — operator payloads outside scope are dropped silently by
              the framework, never bypassing the gate.
            </span>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}