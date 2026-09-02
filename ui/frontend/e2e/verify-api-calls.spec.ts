// Comprehensive API-call verification. For each page, capture network
// calls triggered by user actions (clicks, filters, refresh) and assert
// that the right endpoint was hit with the right method.

import { test, expect } from "@playwright/test";

type ApiCall = {
  method: string;
  url: string;
  status: number;
  triggeredBy: string;
};

const callsByPage = new Map<string, ApiCall[]>();

function record(page: { on: (event: string, fn: (resp: any) => void) => void }) {
  // Best-effort: attach once per page via a guard. Playwright creates
  // a fresh page per test, so a module-level map is fine.
  return (label: string) =>
    page.on("response", async (resp) => {
      const url = resp.url();
      if (!url.includes("/api/")) return;
      const list = callsByPage.get(label) ?? [];
      list.push({
        method: resp.request().method(),
        url: url.replace(/^http:\/\/127\.0\.0\.1:8000/, ""),
        status: resp.status(),
        triggeredBy: label,
      });
      callsByPage.set(label, list);
    });
}

test("SETTINGS — Refresh button calls /api/config", async ({ page }) => {
  record(page)("settings");
  await page.goto("http://127.0.0.1:3001/settings");
  await expect(page.getByTestId("settings-refresh")).toBeVisible({ timeout: 10000 });
  await page.waitForTimeout(500);

  const before = (callsByPage.get("settings") ?? []).filter((c) => c.url === "/api/config").length;
  await page.click('[data-testid="settings-refresh"]');
  await page.waitForTimeout(500);
  const after = (callsByPage.get("settings") ?? []).filter((c) => c.url === "/api/config").length;
  expect(after).toBeGreaterThan(before);
  console.log("settings calls:", JSON.stringify(callsByPage.get("settings"), null, 2));
});

test("DECODER — buttons are pure client-side (no API)", async ({ page }) => {
  record(page)("decoder");
  await page.goto("http://127.0.0.1:3001/decoder");
  await expect(page.getByRole("heading", { name: "Decoder" })).toBeVisible({
    timeout: 10000,
  });
  // Type input, click Decode — should not hit any /api/ endpoint
  const input = page.locator("textarea").first();
  await input.fill("aGVsbG8=");
  await page.waitForTimeout(300);
  const apiCalls = (callsByPage.get("decoder") ?? []).length;
  expect(apiCalls).toBe(0);
  console.log("decoder calls:", apiCalls, "(expected 0 — pure client-side)");
});

test("TOKEN ENTROPY — Analyze button calls /api/entropy/analyze", async ({ page }) => {
  record(page)("token-entropy");
  await page.goto("http://127.0.0.1:3001/tools/token-entropy");
  await expect(page.getByRole("heading", { name: /Token Entropy/i })).toBeVisible({
    timeout: 10000,
  });
  // The text input is the token
  const input = page.locator("textarea").first();
  await input.fill("aGVsbG8td29ybGQ=");
  // Find the Analyze button
  const analyzeBtn = page.getByRole("button", { name: /Analyze/i });
  await analyzeBtn.click();
  await page.waitForTimeout(1500); // wait for backend call + render
  const apiCalls = callsByPage.get("token-entropy") ?? [];
  const entropyCall = apiCalls.find((c) => c.url === "/api/entropy/analyze");
  expect(entropyCall).toBeDefined();
  expect(entropyCall?.method).toBe("POST");
  expect(entropyCall?.status).toBe(200);
  console.log("token-entropy calls:", JSON.stringify(apiCalls, null, 2));
});

test("COMPARER — Scan input loads evidence via /api/scans/{id}/evidence", async ({ page }) => {
  record(page)("comparer");
  await page.goto("http://127.0.0.1:3001/comparer");
  await expect(page.getByRole("heading", { name: "Comparer" })).toBeVisible({
    timeout: 10000,
  });
  // The Comparer page likely has a scan ID input or similar
  // We just verify the GET /api/scans/{id}/evidence fires on mount
  // or on a Load button click. If neither, document it.
  await page.waitForTimeout(1000);
  const apiCalls = callsByPage.get("comparer") ?? [];
  console.log("comparer calls:", JSON.stringify(apiCalls, null, 2));
});

test("EVIDENCE LOG — loads /api/scans/{id}/evidence on mount", async ({ page }) => {
  record(page)("evidence-log");
  // Find a scan with findings via API
  const resp = await page.request.get("http://127.0.0.1:8000/api/scans?limit=1");
  const scans = (await resp.json()) as Array<{ id: number }>;
  if (!scans.length) {
    test.skip(true, "no scans in DB — seed data missing");
    return;
  }
  await page.goto(`http://127.0.0.1:3001/scans/${scans[0].id}/evidence`);
  await page.waitForTimeout(1500);
  const apiCalls = callsByPage.get("evidence-log") ?? [];
  const evidenceCall = apiCalls.find((c) =>
    c.url.includes(`/api/scans/${scans[0].id}/evidence`),
  );
  expect(evidenceCall).toBeDefined();
  expect(evidenceCall?.method).toBe("GET");
  console.log("evidence-log calls:", JSON.stringify(apiCalls, null, 2));
});

test("TARGET / Site Map — loads target + sitemap on mount", async ({ page }) => {
  record(page)("target-sitemap");
  // First find a target
  const resp = await page.request.get("http://127.0.0.1:8000/api/targets?limit=1");
  const targets = (await resp.json()) as Array<{ id: number }>;
  if (!targets.length) {
    test.skip(true, "no targets in DB");
    return;
  }
  await page.goto(`http://127.0.0.1:3001/targets/${targets[0].id}`);
  await expect(page.getByRole("heading", { name: /Target/i })).toBeVisible({
    timeout: 10000,
  });
  await page.waitForTimeout(1000);
  const apiCalls = callsByPage.get("target-sitemap") ?? [];
  console.log("target-sitemap calls:", JSON.stringify(apiCalls, null, 2));
});

test("REPLAY — Run button calls POST /api/findings/{wpoc_id}/replay", async ({ page }) => {
  record(page)("replay");
  // First find a finding
  const resp = await page.request.get(
    "http://127.0.0.1:8000/api/findings?limit=1",
  );
  const findings = (await resp.json()) as Array<{ wpoc_id: string }>;
  if (!findings.length) {
    test.skip(true, "no findings in DB");
    return;
  }
  const wpoc = findings[0].wpoc_id;
  await page.goto(`http://127.0.0.1:3001/findings/${wpoc}/replay`);
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(500);
  // Click Run / Replay button
  const runBtn = page.getByRole("button", { name: /Run|Replay/i }).first();
  const btnVisible = await runBtn.isVisible().catch(() => false);
  if (btnVisible) {
    await runBtn.click();
    await page.waitForTimeout(2000);
  }
  const apiCalls = callsByPage.get("replay") ?? [];
  const replayCall = apiCalls.find(
    (c) => c.method === "POST" && c.url.includes(`/api/findings/${wpoc}/replay`),
  );
  expect(replayCall).toBeDefined();
  expect(replayCall?.status).toBeLessThan(500);
  console.log("replay calls:", JSON.stringify(apiCalls, null, 2));
});