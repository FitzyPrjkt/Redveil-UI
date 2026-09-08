"use client";

// IncludeFpToggle (0.2.0 Phase 8, spec §10)
//
// A checkbox bound to localStorage['redveil-ui:findings:include_fp'].
// When checked, the consumer refetches the findings list with
// ?include_fp=true so suppressed (false-positive) findings surface in
// a muted style. localStorage is per-browser by design (spec §10.4);
// reads are wrapped in try/catch because some browsers/contexts
// (private windows, blocked site data) throw on access.

import { useEffect, useState } from "react";

const STORAGE_KEY = "redveil-ui:findings:include_fp";

export function readIncludeFp(): boolean {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

export function writeIncludeFp(value: boolean): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, value ? "true" : "false");
  } catch {
    // best-effort persistence; the toggle still works in-session
  }
}

export default function IncludeFpToggle({
  onChange,
}: {
  onChange: (includeFp: boolean) => void;
}) {
  const [checked, setChecked] = useState(false);

  // Hydrate from localStorage after mount (SSR-safe).
  useEffect(() => {
    setChecked(readIncludeFp());
  }, []);

  return (
    <label
      data-testid="include-fp-toggle"
      className="inline-flex cursor-pointer select-none items-center gap-2 text-sm text-zinc-400"
    >
      <input
        type="checkbox"
        data-testid="include-fp-checkbox"
        checked={checked}
        onChange={(e) => {
          const next = e.target.checked;
          setChecked(next);
          writeIncludeFp(next);
          onChange(next);
        }}
        className="h-4 w-4 rounded border-zinc-700 bg-zinc-950 accent-amber-500"
      />
      Show suppressed (false positives)
    </label>
  );
}
