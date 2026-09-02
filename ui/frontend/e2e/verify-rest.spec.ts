// Verification screenshots for the remaining 5 pages (settings,
// decoder, comparer, token-entropy, replay). Saves full-page
// screenshots to test-results/.

import { test, expect } from "@playwright/test";

test("settings page renders", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/settings");
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible({
    timeout: 10000,
  });
  // Wait for data to actually load (StatTile for max_requests is
  // bound only after the API fetch resolves).
  await expect(page.getByTestId("settings-section-limits")).toBeVisible({
    timeout: 10000,
  });
  await expect(page.getByText("Max requests").first()).toBeVisible({
    timeout: 5000,
  });
  await page.waitForTimeout(500); // small settle
  await page.screenshot({
    path: "test-results/settings.png",
    fullPage: true,
  });
});

test("decoder page renders", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/decoder");
  await expect(page.getByRole("heading", { name: "Decoder" })).toBeVisible({
    timeout: 10000,
  });
  // Decoder is pure client-side — wait for the static layout
  await page.waitForTimeout(500);
  await page.screenshot({
    path: "test-results/decoder.png",
    fullPage: true,
  });
});

test("comparer page renders", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/comparer");
  await expect(page.getByRole("heading", { name: "Comparer" })).toBeVisible({
    timeout: 10000,
  });
  await page.waitForTimeout(500);
  await page.screenshot({
    path: "test-results/comparer.png",
    fullPage: true,
  });
});

test("token-entropy page renders", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/tools/token-entropy");
  await expect(
    page.getByRole("heading", { name: /Token Entropy/i }),
  ).toBeVisible({ timeout: 10000 });
  await page.waitForTimeout(500);
  await page.screenshot({
    path: "test-results/token-entropy.png",
    fullPage: true,
  });
});

test("finding detail renders", async ({ page }) => {
  // Resolve a real finding ID from the seeded DB
  const resp = await page.request.get("http://127.0.0.1:8000/api/findings?limit=1");
  const findings = (await resp.json()) as Array<{ wpoc_id: string }>;
  if (!findings.length) {
    test.skip(true, "no findings in DB");
    return;
  }
  const wpoc = findings[0].wpoc_id;
  await page.goto(`http://127.0.0.1:3001/findings/${wpoc}`);
  // Wait for the title to render (data loaded) OR the not-found alert
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(800);
  await page.screenshot({
    path: "test-results/finding-detail.png",
    fullPage: true,
  });
});

test("replay page renders", async ({ page }) => {
  // Resolve a real finding ID from the seeded DB
  const resp = await page.request.get("http://127.0.0.1:8000/api/findings?limit=1");
  const findings = (await resp.json()) as Array<{ wpoc_id: string }>;
  if (!findings.length) {
    test.skip(true, "no findings in DB");
    return;
  }
  const wpoc = findings[0].wpoc_id;
  await page.goto(`http://127.0.0.1:3001/findings/${wpoc}/replay`);
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(800);
  await page.screenshot({
    path: "test-results/replay.png",
    fullPage: true,
  });
});