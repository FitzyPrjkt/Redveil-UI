"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { IconAlertTriangle, IconCircleCheck } from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { apiPost } from "@/lib/api";
import { cn } from "@/lib/utils";

type Profile = "passive" | "low_impact" | "active";
type DestructiveLevel = "L1" | "L2" | "L3" | "L4" | "L5" | "L6";
type GateMode = "non_interactive" | "strict" | "interactive";

interface Target {
  id: number;
  url: string;
  name: string | null;
  scope_yaml: string | null;
}

interface Scan {
  id: number;
  target_id: number;
  status: string;
  profile: string;
  started_at: string | null;
  completed_at: string | null;
  output_dir: string | null;
  total_requests: number;
  error: string | null;
}

const LEVEL_OPTIONS: {
  value: DestructiveLevel;
  label: string;
  description: string;
}[] = [
  { value: "L1", label: "L1 — Data Exfiltration", description: "read-only" },
  { value: "L2", label: "L2 — Data Modification", description: "default" },
  { value: "L3", label: "L3 — Data Destruction", description: "risky" },
  { value: "L4", label: "L4 — Persistence", description: "dangerous" },
  { value: "L5", label: "L5 — Lateral Movement", description: "critical" },
  { value: "L6", label: "L6 — Takeover", description: "maximum" },
];

function levelColor(level: DestructiveLevel): string {
  if (level === "L1" || level === "L2")
    return "bg-yellow-500/15 text-yellow-300 border-yellow-500/30";
  if (level === "L3" || level === "L4")
    return "bg-orange-500/15 text-orange-300 border-orange-500/30";
  return "bg-red-500/15 text-red-300 border-red-500/30";
}

const GATE_OPTIONS: { value: GateMode; label: string; description: string; disabled?: boolean }[] = [
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
    label: "Interactive — Coming in v2",
    description: "prompts per action via WebSocket",
    disabled: true,
  },
];

// Active profile runs both Time-Based SQLi (worst case 640 requests) and
// Command Injection (worst case 1190 requests). 1500 covers both checks
// in one scan with a small buffer for other active checks. Operators
// picking active profile get a warning if they set a value below this.
const ACTIVE_RECOMMENDED_MIN = 1500;

export default function NewScanPage() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [scopeYaml, setScopeYaml] = useState("");
  const [profile, setProfile] = useState<Profile>("passive");
  const [level, setLevel] = useState<DestructiveLevel>("L2");
  const [allowDestructive, setAllowDestructive] = useState(false);
  const [gateMode, setGateMode] = useState<GateMode>("non_interactive");
  const [maxRequests, setMaxRequests] = useState<string>("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const levelSwatch = useMemo(() => levelColor(level), [level]);

  // Active profile needs ~1500 requests worst-case for the active checks
  // (Time-Based SQLi + Command Injection). Warn when the operator sets a
  // value below that so the scan doesn't get cut off mid-probe.
  const isActiveProfile = profile === "active";
  const parsedMaxRequests = Number(maxRequests);
  const belowActiveMin =
    isActiveProfile &&
    maxRequests.trim() !== "" &&
    Number.isFinite(parsedMaxRequests) &&
    parsedMaxRequests > 0 &&
    parsedMaxRequests < ACTIVE_RECOMMENDED_MIN;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const trimmedUrl = url.trim();
      if (!trimmedUrl) {
        throw new Error("URL wajib diisi");
      }
      const targetBody: {
        url: string;
        name?: string;
        scope_yaml?: string;
      } = { url: trimmedUrl };
      const trimmedName = name.trim();
      if (trimmedName) targetBody.name = trimmedName;
      const trimmedScope = scopeYaml.trim();
      if (trimmedScope) targetBody.scope_yaml = trimmedScope;

      const target = await apiPost<Target>("/api/targets", targetBody);

      const scanBody: {
        target_id: number;
        profile: Profile;
        scope_yaml?: string;
        max_destructive_level: DestructiveLevel;
        allow_destructive: boolean;
        gate_mode: GateMode;
        max_requests?: number;
      } = {
        target_id: target.id,
        profile,
        max_destructive_level: level,
        allow_destructive: allowDestructive,
        gate_mode: gateMode,
      };
      if (trimmedScope) scanBody.scope_yaml = trimmedScope;
      const maxReqNum = Number(maxRequests);
      if (maxRequests.trim() && Number.isFinite(maxReqNum) && maxReqNum > 0) {
        scanBody.max_requests = maxReqNum;
      }

      const scan = await apiPost<Scan>("/api/scans", scanBody);
      router.push(`/scans/${scan.id}`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-8">
      <header className="space-y-2">
        <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
          New Scan
        </h1>
        <p className="text-sm text-zinc-400">
          Daftarkan target baru dan jalankan scan dengan profile, destructive
          ceiling, dan gate mode tertentu.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="space-y-6" data-testid="new-scan-form">
        <Card className="space-y-4 rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">
            Target
          </h2>

          <div className="space-y-2">
            <Label htmlFor="url" className="text-zinc-200">
              URL <span className="text-red-400">*</span>
            </Label>
            <Input
              id="url"
              data-testid="scan-url"
              type="url"
              required
              placeholder="https://staging.example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="border-zinc-700 bg-zinc-950 text-zinc-100 placeholder:text-zinc-500"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="name" className="text-zinc-200">
              Name <span className="text-zinc-500">(optional)</span>
            </Label>
            <Input
              id="name"
              type="text"
              placeholder="staging-app"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="border-zinc-700 bg-zinc-950 text-zinc-100 placeholder:text-zinc-500"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="scope" className="text-zinc-200">
              Scope YAML <span className="text-zinc-500">(optional)</span>
            </Label>
            <textarea
              id="scope"
              data-testid="scan-scope"
              rows={4}
              placeholder={"allow:\n  - staging.example.com\ndeny:\n  - admin.*"}
              value={scopeYaml}
              onChange={(e) => setScopeYaml(e.target.value)}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-500 focus:outline-none"
            />
          </div>
        </Card>

        <Card className="space-y-4 rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-zinc-400">
            Scan profile
          </h2>

          <div className="space-y-2">
            <Label className="text-zinc-200">Profile</Label>
            <RadioGroup
              value={profile}
              onValueChange={(v) => setProfile(v as Profile)}
              className="grid gap-2 sm:grid-cols-3"
            >
              <Label
                htmlFor="profile-passive"
                className="flex cursor-pointer items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-950 p-3 hover:border-zinc-700"
              >
                <RadioGroupItem id="profile-passive" value="passive" />
                <div className="space-y-1">
                  <div className="text-sm font-medium text-zinc-100">passive</div>
                  <div className="text-xs text-zinc-500">read-only recon</div>
                </div>
              </Label>
              <Label
                htmlFor="profile-low"
                className="flex cursor-pointer items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-950 p-3 hover:border-zinc-700"
              >
                <RadioGroupItem id="profile-low" value="low_impact" />
                <div className="space-y-1">
                  <div className="text-sm font-medium text-zinc-100">low_impact</div>
                  <div className="text-xs text-zinc-500">non-destructive probes</div>
                </div>
              </Label>
              <Label
                htmlFor="profile-active"
                className="flex cursor-pointer items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-950 p-3 hover:border-zinc-700"
              >
                <RadioGroupItem id="profile-active" value="active" />
                <div className="space-y-1">
                  <div className="text-sm font-medium text-zinc-100">active</div>
                  <div className="text-xs text-zinc-500">exploitation-grade</div>
                </div>
              </Label>
            </RadioGroup>
          </div>

          <div className="space-y-2">
            <Label htmlFor="destructive-level" className="text-zinc-200">
              Destructive level ceiling
            </Label>
            <div className="flex items-center gap-2">
              <span
                aria-hidden="true"
                className={cn(
                  "h-2.5 w-2.5 shrink-0 rounded-full border",
                  levelSwatch,
                )}
              />
              <select
                id="destructive-level"
                data-testid="scan-level"
                value={level}
                onChange={(e) => setLevel(e.target.value as DestructiveLevel)}
                className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
              >
                {LEVEL_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
            <p className="text-xs text-zinc-500">
              {LEVEL_OPTIONS.find((o) => o.value === level)?.description} —{" "}
              ceiling ini menentukan seberapa invasive check boleh berjalan
              bahkan saat allow_destructive aktif.
            </p>
          </div>

          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <input
                id="allow-destructive"
                data-testid="scan-allow-destructive"
                type="checkbox"
                checked={allowDestructive}
                onChange={(e) => setAllowDestructive(e.target.checked)}
                className="h-4 w-4 cursor-pointer rounded border-zinc-600 bg-zinc-950 text-red-500 focus:ring-2 focus:ring-red-500/30 focus:ring-offset-0"
              />
              <label
                htmlFor="allow-destructive"
                className="cursor-pointer text-sm text-zinc-300"
              >
                Allow destructive actions
              </label>
            </div>
            {allowDestructive ? (
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
                  Findings pada level ini bisa mengubah atau merusak data di
                  target. Pastikan kamu punya izin eksplisit.
                </span>
              </div>
            ) : null}
          </div>

          <div className="space-y-2">
            <Label htmlFor="gate-mode" className="text-zinc-200">
              Gate mode
            </Label>
            <select
              id="gate-mode"
              data-testid="scan-gate-mode"
              value={gateMode}
              onChange={(e) => setGateMode(e.target.value as GateMode)}
              className="h-8 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-2 text-sm text-zinc-100 focus:border-zinc-500 focus:outline-none"
            >
              {GATE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value} disabled={opt.disabled}>
                  {opt.label}
                </option>
              ))}
            </select>
            <p className="text-xs text-zinc-500">
              {GATE_OPTIONS.find((o) => o.value === gateMode)?.description}
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="max-requests" className="text-zinc-200">
              Max requests <span className="text-zinc-500">(optional)</span>
            </Label>
            <Input
              id="max-requests"
              data-testid="scan-max-requests"
              type="number"
              min={1}
              placeholder={isActiveProfile ? String(ACTIVE_RECOMMENDED_MIN) : "unlimited"}
              value={maxRequests}
              onChange={(e) => setMaxRequests(e.target.value)}
              className="border-zinc-700 bg-zinc-950 text-zinc-100 placeholder:text-zinc-500"
            />
            <p className="text-xs text-zinc-500">
              Batasi total request agar tidak menabrak rate-limit target.
            </p>
            {isActiveProfile ? (
              <p className="text-xs text-zinc-500">
                Rekomendasi minimum untuk profile{" "}
                <span className="font-mono text-zinc-300">active</span>:{" "}
                <span
                  className="font-mono text-zinc-300"
                  data-testid="scan-max-requests-min"
                >
                  {ACTIVE_RECOMMENDED_MIN}
                </span>{" "}
                request (Time-Based SQLi 640 + Command Injection 1190 worst
                case). Kosongkan untuk unlimited.
              </p>
            ) : null}
            {belowActiveMin ? (
              <div
                role="alert"
                data-testid="scan-max-requests-below-min"
                className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm text-yellow-300"
              >
                <IconAlertTriangle
                  size={16}
                  className="mt-0.5 shrink-0"
                  aria-hidden="true"
                />
                <span>
                  Budget {parsedMaxRequests} di bawah rekomendasi minimum
                  {" "}
                  {ACTIVE_RECOMMENDED_MIN} untuk profile active — scan
                  bisa ke-stop di tengah probe dan check aktif (SQLi,
                  Command Injection) tidak akan jalan penuh.
                </span>
              </div>
            ) : null}
          </div>
        </Card>

        {error ? (
          <div
            role="alert"
            className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
          >
            {error}
          </div>
        ) : null}

        <div className="flex items-center justify-end gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => router.push("/scans")}
            disabled={submitting}
          >
            Cancel
          </Button>
          <Button
            type="submit"
            data-testid="scan-submit"
            disabled={submitting}
            className="gap-1.5"
          >
            {submitting ? (
              "Starting scan…"
            ) : (
              <>
                <IconCircleCheck size={14} aria-hidden="true" />
                Start scan
              </>
            )}
          </Button>
        </div>
      </form>
    </div>
  );
}
