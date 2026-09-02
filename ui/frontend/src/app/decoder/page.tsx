"use client";

import { useCallback, useMemo, useState } from "react";
import {
  IconArrowsRightLeft,
  IconArrowDown,
  IconCopy,
  IconCheck,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

type Mode = "base64" | "url" | "html" | "hex";
type Direction = "encode" | "decode";

const MODES: { id: Mode; label: string }[] = [
  { id: "base64", label: "Base64" },
  { id: "url", label: "URL" },
  { id: "html", label: "HTML" },
  { id: "hex", label: "Hex" },
];

// ---- Mode implementations ------------------------------------------------
//
// Each function returns null on failure (e.g. invalid Base64) so the UI
// can render the original input rather than blowing up.

function encodeBase64(s: string): string | null {
  try {
    // btoa needs Latin-1; encode non-ASCII as UTF-8 first.
    const bytes = new TextEncoder().encode(s);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  } catch {
    return null;
  }
}

function decodeBase64(s: string): string | null {
  try {
    const trimmed = s.replace(/\s+/g, "");
    const binary = atob(trimmed);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

function encodeUrl(s: string): string {
  return encodeURIComponent(s);
}

function decodeUrl(s: string): string | null {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

function encodeHtml(s: string): string {
  // Encode the five XML/HTML special characters plus a handful of others
  // attackers commonly exploit. Covers OWASP-recommended escaping.
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/\//g, "&#x2F;");
}

function decodeHtml(s: string): string | null {
  if (typeof document === "undefined") return null;
  // Use the DOM to decode named + numeric entities safely.
  const ta = document.createElement("textarea");
  ta.innerHTML = s;
  return ta.value;
}

function toHex(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

function fromHex(s: string): string | null {
  const cleaned = s.replace(/0x|\s+/g, "").toLowerCase();
  if (cleaned.length % 2 !== 0) return null;
  if (!/^[0-9a-f]*$/.test(cleaned)) return null;
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleaned.substr(i * 2, 2), 16);
  }
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

function run(mode: Mode, direction: Direction, input: string): string | null {
  switch (mode) {
    case "base64":
      return direction === "encode" ? encodeBase64(input) : decodeBase64(input);
    case "url":
      return direction === "encode" ? encodeUrl(input) : decodeUrl(input);
    case "html":
      return direction === "encode" ? encodeHtml(input) : decodeHtml(input);
    case "hex":
      return direction === "encode" ? toHex(input) : fromHex(input);
  }
}

export default function DecoderPage() {
  const [mode, setMode] = useState<Mode>("base64");
  const [direction, setDirection] = useState<Direction>("decode");
  const [input, setInput] = useState("cmVkdmVpbFhTU1Byb2Jl");
  const [copied, setCopied] = useState(false);

  // Compute output during render via useMemo so the output is always
  // in sync with the input / mode / direction — no effect lag, no extra
  // render.
  const { output, error } = useMemo<{
    output: string;
    error: string | null;
  }>(() => {
    const result = run(mode, direction, input);
    if (result === null) {
      return {
        output: "",
        error:
          direction === "decode"
            ? `Invalid ${mode} input — could not decode.`
            : `Could not encode to ${mode}.`,
      };
    }
    return { output: result, error: null };
  }, [input, mode, direction]);

  const outputLabel = useMemo(
    () => (direction === "decode" ? "Output (decoded)" : "Output (encoded)"),
    [direction],
  );

  const swap = useCallback(() => {
    if (output.length === 0) return;
    setInput(output);
    setDirection((d) => (d === "encode" ? "decode" : "encode"));
  }, [output]);

  const copy = useCallback(async () => {
    if (!output) return;
    try {
      await navigator.clipboard.writeText(output);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore — older browsers / non-secure contexts
    }
  }, [output]);

  return (
    <div className="space-y-8">
      <header className="space-y-2">
        <h1 className="font-serif text-3xl font-bold tracking-tight text-zinc-100">
          Decoder
        </h1>
        <p className="text-sm text-zinc-400">
          Standalone encode / decode utility for Base64, URL, HTML entities,
          and Hex. Pure client-side — values never leave the browser.
        </p>
      </header>

      <Card className="rounded-xl border border-zinc-800 bg-zinc-900 p-6">
        <div className="space-y-4">
          {/* Mode tabs */}
          <div
            role="tablist"
            aria-label="Encoding mode"
            className="flex flex-wrap items-center gap-2"
          >
            {MODES.map((m) => (
              <button
                key={m.id}
                role="tab"
                aria-selected={mode === m.id}
                data-testid={`decoder-mode-${m.id}`}
                onClick={() => setMode(m.id)}
                className={cn(
                  "rounded-lg px-4 py-2 text-sm font-medium transition-colors",
                  mode === m.id
                    ? "bg-sky-600 text-white"
                    : "text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100",
                )}
              >
                {m.label}
              </button>
            ))}

            <div className="ml-auto flex items-center gap-1 rounded-lg border border-zinc-800 bg-zinc-950 p-1">
              <button
                onClick={() => setDirection("decode")}
                data-testid="decoder-dir-decode"
                className={cn(
                  "rounded-md px-3 py-1 text-xs font-medium",
                  direction === "decode"
                    ? "bg-zinc-800 text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-300",
                )}
              >
                Decode
              </button>
              <button
                onClick={() => setDirection("encode")}
                data-testid="decoder-dir-encode"
                className={cn(
                  "rounded-md px-3 py-1 text-xs font-medium",
                  direction === "encode"
                    ? "bg-zinc-800 text-zinc-100"
                    : "text-zinc-500 hover:text-zinc-300",
                )}
              >
                Encode
              </button>
            </div>
          </div>

          {/* Two-pane layout */}
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="space-y-2">
              <label
                htmlFor="decoder-input"
                className="text-sm font-medium text-zinc-300"
              >
                Input
              </label>
              <textarea
                id="decoder-input"
                data-testid="decoder-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                rows={10}
                spellCheck={false}
                className="w-full resize-y rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-100 placeholder:text-zinc-500 focus:border-zinc-500 focus:outline-none"
                placeholder="Paste or type text to encode / decode…"
              />
              <div className="flex items-center justify-between text-xs text-zinc-500">
                <span>{input.length} chars</span>
                <button
                  type="button"
                  onClick={() => setInput("")}
                  className="text-zinc-500 hover:text-zinc-300"
                >
                  Clear
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label
                  htmlFor="decoder-output"
                  className="text-sm font-medium text-zinc-300"
                >
                  {outputLabel}
                </label>
                <div className="flex items-center gap-1">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={swap}
                    disabled={!output}
                    data-testid="decoder-swap"
                    className="gap-1 text-xs"
                  >
                    <IconArrowsRightLeft size={14} aria-hidden="true" />
                    Swap
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={copy}
                    disabled={!output}
                    data-testid="decoder-copy"
                    className="gap-1 text-xs"
                  >
                    {copied ? (
                      <IconCheck size={14} aria-hidden="true" />
                    ) : (
                      <IconCopy size={14} aria-hidden="true" />
                    )}
                    {copied ? "Copied" : "Copy"}
                  </Button>
                </div>
              </div>
              <textarea
                id="decoder-output"
                data-testid="decoder-output"
                readOnly
                value={output}
                rows={10}
                spellCheck={false}
                className={cn(
                  "w-full resize-y rounded-lg border bg-zinc-950 px-3 py-2 font-mono text-sm focus:outline-none",
                  error
                    ? "border-red-500/40 text-red-300"
                    : "border-zinc-700 text-zinc-100",
                )}
                placeholder={
                  error ?? "Output will appear here as you type."
                }
              />
              <div className="flex items-center justify-between text-xs text-zinc-500">
                <span>{output.length} chars</span>
              </div>
            </div>
          </div>

          {/* Hint */}
          <div className="flex items-center gap-2 text-xs text-zinc-500">
            <IconArrowDown size={14} aria-hidden="true" />
            <span>
              {direction === "decode"
                ? `Decoding ${mode} input from the left pane.`
                : `Encoding ${mode} input from the left pane.`}
            </span>
          </div>
        </div>
      </Card>
    </div>
  );
}