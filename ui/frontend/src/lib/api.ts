// API base: relative URL by default. The Next.js bundle is served by
// the same uvicorn process that owns /api/*, so the browser hits the
// same origin and no port discovery is needed. Operators who put
// the UI behind a reverse proxy on a different host can set
// NEXT_PUBLIC_API_BASE (or the public Vercel-style equivalent) to
// override.
const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "";

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

export async function apiPatch<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

export function sseUrl(scanId: number | string): string {
  return `${API_BASE}/api/scans/${scanId}/stream`;
}