import { test, expect } from "@playwright/test";

const BASE = process.env.REDVEIL_TEST_BASE ?? "http://127.0.0.1:8000";

test.describe("Audit A2 — detail pages render correct content", () => {
  test("/scans/1 — must NOT show Dashboard testid", async ({ page }) => {
    const resp = await page.goto(BASE + "/scans/1", { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(1500);
    const body = await page.content();
    expect(resp?.status()).toBe(200);
    // The Dashboard testid should NOT be present — we want the scan detail
    const hasDashboard = body.includes('data-testid="dashboard"');
    expect(hasDashboard, "should NOT render Dashboard testid").toBe(false);
  });

  test("/scans/1/evidence — must NOT show Dashboard", async ({ page }) => {
    const resp = await page.goto(BASE + "/scans/1/evidence", { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(1500);
    const body = await page.content();
    expect(resp?.status()).toBe(200);
    const hasDashboard = body.includes('data-testid="dashboard"');
    expect(hasDashboard, "should NOT render Dashboard testid").toBe(false);
  });

  test("/findings/WPOC-SEED-001 — must show the actual finding, not Dashboard", async ({ page }) => {
    const resp = await page.goto(BASE + "/findings/WPOC-SEED-001", { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(1500);
    const body = await page.content();
    expect(resp?.status()).toBe(200);
    // Must show the seeded finding title
    expect(body, "must contain the finding title").toContain("Seeded Test Finding");
    const hasDashboard = body.includes('data-testid="dashboard"');
    expect(hasDashboard, "should NOT render Dashboard testid").toBe(false);
  });

  test("/findings/WPOC-SEED-001/replay — must NOT show Dashboard", async ({ page }) => {
    const resp = await page.goto(BASE + "/findings/WPOC-SEED-001/replay", { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(1500);
    const body = await page.content();
    expect(resp?.status()).toBe(200);
    const hasDashboard = body.includes('data-testid="dashboard"');
    expect(hasDashboard, "should NOT render Dashboard testid").toBe(false);
  });

  test("/targets/1 — must NOT show Dashboard", async ({ page }) => {
    const resp = await page.goto(BASE + "/targets/1", { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(1500);
    const body = await page.content();
    expect(resp?.status()).toBe(200);
    const hasDashboard = body.includes('data-testid="dashboard"');
    expect(hasDashboard, "should NOT render Dashboard testid").toBe(false);
  });
});
