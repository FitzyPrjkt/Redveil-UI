"use client";

import { useEffect, useState } from "react";
import { IconFileCode, IconAlertTriangle, IconCircleCheck, IconTrash } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { apiGet, apiPost, apiDelete } from "@/lib/api";

interface Endpoint {
  method: string;
  path: string;
  parameters: { name: string; location: string }[];
  source: string;
}

interface SpecOut {
  id: number;
  name: string | null;
  spec: string;
  created_at: string;
  endpoints: Endpoint[] | null;
  count: number;
}

export default function OpenApiPage() {
  const [spec, setSpec] = useState("");
  const [name, setName] = useState("");
  const [preview, setPreview] = useState<Endpoint[]>([]);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [previewCount, setPreviewCount] = useState(0);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [specs, setSpecs] = useState<SpecOut[]>([]);
  const [loadingList, setLoadingList] = useState(true);

  async function loadList() {
    setLoadingList(true);
    try {
      const data = await apiGet<SpecOut[]>("/api/openapi/specs");
      setSpecs(data);
    } catch {
      // ignore
    } finally {
      setLoadingList(false);
    }
  }

  useEffect(() => {
    loadList();
  }, []);

  async function handlePreview() {
    setPreviewError(null);
    setLoadingPreview(true);
    try {
      const res = await apiPost<{ endpoints: Endpoint[]; count: number; error: string | null }>("/api/openapi/parse", { spec });
      if (res.error) {
        setPreviewError(res.error);
        setPreview([]);
        setPreviewCount(0);
      } else {
        setPreview(res.endpoints);
        setPreviewCount(res.count);
      }
    } catch (e: unknown) {
      setPreviewError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingPreview(false);
    }
  }

  async function handleSave() {
    setSaveError(null);
    setSaving(true);
    try {
      await apiPost("/api/openapi/specs", { name: name.trim() || null, spec });
      setSpec("");
      setName("");
      setPreview([]);
      setPreviewCount(0);
      setPreviewError(null);
      await loadList();
    } catch (e: unknown) {
      setSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    try {
      await apiDelete(`/api/openapi/specs/${id}`);
      await loadList();
    } catch (e: unknown) {
      console.error(e);
    }
  }

  return (
    <div className="mx-auto max-w-5xl space-y-8" data-testid="openapi-page">
      <header className="space-y-2">
        <h1 className="flex items-center gap-2 font-sans text-3xl font-semibold tracking-tight text-zinc-100">
          <IconFileCode size={24} className="text-zinc-400" />
          OpenAPI
        </h1>
        <p className="text-sm text-zinc-400">
          Import OpenAPI/Swagger spec, preview endpoints yang ter-parse, validasi sebelum scan. Mengikuti <span className="font-mono text-zinc-300">DESIGN.md</span> token.
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="space-y-4 rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Import Spec</h2>
          <div className="space-y-2">
            <Label htmlFor="openapi-name" className="text-zinc-200">Name <span className="text-zinc-500">(optional)</span></Label>
            <Input
              id="openapi-name"
              placeholder="my-api-v1"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="border-zinc-700 bg-zinc-950 text-zinc-100 placeholder:text-zinc-500"
              data-testid="openapi-name"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="openapi-spec" className="text-zinc-200">Spec <span className="text-red-400">*</span> <span className="font-mono text-xs text-zinc-500">(yaml/json)</span></Label>
            <textarea
              id="openapi-spec"
              rows={14}
              placeholder={"openapi: 3.0.0\ninfo:\n  title: Demo\n  version: 1.0.0\npaths:\n  /api/users:\n    get:\n      parameters:\n        - name: id\n          in: query"}
              value={spec}
              onChange={(e) => setSpec(e.target.value)}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-500 focus:outline-none"
              data-testid="openapi-spec"
            />
          </div>
          <div className="flex gap-2">
            <Button onClick={handlePreview} disabled={!spec.trim() || loadingPreview} variant="outline" data-testid="openapi-preview">
              {loadingPreview ? "Validating..." : "Preview"}
            </Button>
            <Button onClick={handleSave} disabled={!spec.trim() || saving} data-testid="openapi-save">
              {saving ? "Saving..." : "Save"}
            </Button>
            <Button onClick={() => { setSpec(""); setPreview([]); setPreviewError(null); }} variant="outline">Clear</Button>
          </div>
          {previewError ? (
            <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300" data-testid="openapi-error">
              <IconAlertTriangle size={16} className="mt-0.5 shrink-0" />
              <span>{previewError}</span>
            </div>
          ) : null}
          {previewCount > 0 && !previewError ? (
            <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-300" data-testid="openapi-preview-ok">
              <IconCircleCheck size={16} className="shrink-0" />
              <span>{previewCount} endpoints parsed</span>
              <span className="ml-auto rounded-full bg-zinc-800 px-2 py-0.5 font-mono text-xs text-zinc-300">{previewCount}</span>
            </div>
          ) : null}
          {saveError ? (
            <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">{saveError}</div>
          ) : null}
        </Card>

        <Card className="space-y-4 rounded-xl border border-zinc-800 bg-zinc-900 p-5" data-testid="openapi-preview">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Preview</h2>
          {preview.length === 0 ? (
            <p className="text-sm text-zinc-500">Belum ada preview. Paste spec dan klik Preview.</p>
          ) : (
            <div className="overflow-auto rounded-lg border border-zinc-800">
              <table className="w-full text-left font-mono text-sm">
                <thead className="bg-zinc-950 text-xs uppercase tracking-wider text-zinc-400">
                  <tr>
                    <th className="px-3 py-2">Method</th>
                    <th className="px-3 py-2">Path</th>
                    <th className="px-3 py-2">Params</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {preview.slice(0, 20).map((ep, i) => (
                    <tr key={i} className="text-zinc-300">
                      <td className="px-3 py-2"><span className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs">{ep.method}</span></td>
                      <td className="px-3 py-2">{ep.path}</td>
                      <td className="px-3 py-2 text-xs text-zinc-500">{ep.parameters.map((p) => `${p.name}(${p.location})`).join(", ") || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {preview.length > 20 ? <p className="p-2 text-center text-xs text-zinc-500">+{preview.length - 20} more</p> : null}
            </div>
          )}
        </Card>
      </div>

      <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-5" data-testid="openapi-list">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">Saved specs</h2>
        {loadingList ? (
          <p className="mt-3 text-sm text-zinc-500">Loading…</p>
        ) : specs.length === 0 ? (
          <p className="mt-3 text-sm text-zinc-500">Belum ada spec tersimpan.</p>
        ) : (
          <div className="mt-3 space-y-2">
            {specs.map((s) => (
              <div key={s.id} className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-950 px-3 py-2">
                <div className="space-y-1">
                  <div className="font-mono text-sm text-zinc-100">{s.name || `spec-${s.id}`} <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">{s.count} endpoints</span></div>
                  <div className="text-xs text-zinc-500">{new Date(s.created_at).toLocaleString()}</div>
                </div>
                <Button variant="outline" size="sm" onClick={() => handleDelete(s.id)} data-testid={`openapi-delete-${s.id}`}>
                  <IconTrash size={14} /> Delete
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
