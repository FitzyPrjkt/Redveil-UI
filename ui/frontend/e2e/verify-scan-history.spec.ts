/* Verify Scan History + Scan Detail pages render and call backend. */
import { test, expect, type Page } from "@playwright/test";

const BASE = "http://127.0.0.1:3001";

test("SCAN HISTORY — list page renders, fetches /api/scans + /api/targets", async ({
  page,
}) => {
  // Wait for both API calls before checking the buffer. The page
  // issues them in parallel on mount.
  const scansResponse = page.waitForResponse(
    (r) =>
      r.url().includes("/api/scans") &&
      !r.url().includes("/evidence") &&
      r.request().method() === "GET",
  );
  const targetsResponse = page.waitForResponse(
    (r) => r.url().includes("/api/targets") && r.request().method() === "GET",
  );
  await page.goto(`${BASE}/scans`, { waitUntil: "domcontentloaded" });
  const [scans, targets] = await Promise.all([scansResponse, targetsResponse]);
  expect(scans.status()).toBeLessThan(500);
  expect(targets.status()).toBeLessThan(500);

  // Header
  await expect(
    page.getByTestId("scan-history-title"),
  ).toHaveText("Scan history");

  // Stat tiles populate (real data, not mock)
  await expect(page.getByTestId("stat-total")).toBeVisible();
  await expect(page.getByTestId("stat-running")).toBeVisible();
  // The stat-total should reflect a real number from /api/scans
  const totalText = await page.getByTestId("stat-total").textContent();
  expect(Number(totalText)).toBeGreaterThan(0);

  // Scan list rendered
  await expect(page.getByTestId("scan-list")).toBeVisible({ timeout: 10000 });
  await expect(page.getByTestId("scan-card").first()).toBeVisible();

  // Filter chips + search box
  await expect(page.getByTestId("scan-filter-all")).toBeVisible();
  await expect(page.getByTestId("scan-filter-running")).toBeVisible();
  await expect(page.getByTestId("scan-filter-completed")).toBeVisible();
  await expect(page.getByTestId("scan-filter-failed")).toBeVisible();
  await expect(page.getByTestId("scan-search")).toBeVisible();
});

test("SCAN HISTORY — search filters the list client-side", async ({ page }) => {
  await page.goto(`${BASE}/scans`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("scan-list")).toBeVisible({ timeout: 10000 });
  const beforeCount = await page.getByTestId("scan-card").count();
  expect(beforeCount).toBeGreaterThan(0);

  // Type a query that matches nothing
  await page.getByTestId("scan-search").fill("__no_match_zzz__");
  await page.waitForTimeout(300);
  expect(await page.getByTestId("scan-card").count()).toBe(0);
  await expect(page.getByRole("status")).toBeVisible();

  // Clear search -> cards back
  await page.getByTestId("scan-search").fill("");
  await page.waitForTimeout(300);
  expect(await page.getByTestId("scan-card").count()).toBe(beforeCount);
});

test("SCAN DETAIL — page renders, fetches scan + findings + target", async ({
  page,
}) => {
  // Find an existing scan via the API directly
  const scansApiResponse = page.waitForResponse(
    (r) => r.url().includes("/api/scans?") && r.request().method() === "GET",
  );
  await page.goto(`${BASE}/scans`, { waitUntil: "domcontentloaded" });
  await scansApiResponse;
  await expect(page.getByTestId("scan-list")).toBeVisible({ timeout: 10000 });

  const firstCard = page.getByTestId("scan-card").first();
  await expect(firstCard).toBeVisible({ timeout: 10000 });
  const href = await firstCard.getAttribute("href");
  expect(href).toMatch(/\/scans\/\d+/);

  // Wait for detail page's API calls (3 in parallel: scan, findings, target)
  const scanResponse = page.waitForResponse(
    (r) => /\/api\/scans\/\d+$/.test(r.url()) && r.request().method() === "GET",
  );
  const findingsResponse = page.waitForResponse(
    (r) => r.url().includes("/findings") && r.request().method() === "GET",
  );
  const targetResponse = page.waitForResponse(
    (r) => r.url().includes("/api/targets/") && r.request().method() === "GET",
  );
  await firstCard.click();
  await page.waitForURL(/\/scans\/\d+$/);
  const [scan, findings, target] = await Promise.all([
    scanResponse,
    findingsResponse,
    targetResponse,
  ]);
  expect(scan.status()).toBeLessThan(500);
  expect(findings.status()).toBeLessThan(500);
  expect(target.status()).toBeLessThan(500);

  // Header
  await expect(page.getByTestId("scan-target")).toBeVisible();
  await expect(page.getByTestId("scan-status")).toBeVisible();
  // Tabs
  await expect(page.getByTestId("tab-findings")).toBeVisible();
  await expect(page.getByTestId("tab-sitemap")).toBeVisible();
  await expect(page.getByTestId("tab-evidence")).toBeVisible();
  // Severity tiles
  await expect(page.getByTestId("severity-high")).toBeVisible();
  await expect(page.getByTestId("severity-medium")).toBeVisible();
  await expect(page.getByTestId("severity-low")).toBeVisible();
  // Progress bar
  await expect(page.getByTestId("scan-progress")).toBeVisible();
});

test("SCAN DETAIL — clicking a finding card navigates to finding detail", async ({
  page,
}) => {
  await page.goto(`${BASE}/scans`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("scan-list")).toBeVisible({ timeout: 10000 });
  const firstCard = page.getByTestId("scan-card").first();
  await expect(firstCard).toBeVisible({ timeout: 10000 });
  await firstCard.click();
  await page.waitForURL(/\/scans\/\d+$/);
  // Wait for findings to load
  await page.waitForTimeout(800);
  const firstFinding = page.getByTestId("finding-card").first();
  if ((await firstFinding.count()) > 0) {
    await firstFinding.click();
    await page.waitForURL(/\/findings\/WPOC-/);
    await expect(page.getByTestId("finding-title")).toBeVisible();
  }
});

test("SCAN DETAIL — invalid id shows error", async ({ page }) => {
  await page.goto(`${BASE}/scans/99999`);
  await expect(
    page.getByText("Scan #99999 not found"),
  ).toBeVisible({ timeout: 10000 });
});