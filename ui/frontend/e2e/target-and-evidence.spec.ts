import { test, expect } from "@playwright/test";

test("target page renders 3 tabs with site map, scope, issue defs", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/targets/1");
  await expect(page.getByRole("heading", { name: "Target" })).toBeVisible();

  // Tabs are present
  await expect(page.getByRole("tab", { name: "Site map" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Scope" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Issue defs" })).toBeVisible();

  // Site map view renders (testid can be off-screen but DOM is present)
  await expect(page.getByTestId("sitemap-view")).toBeVisible({ timeout: 10000 });

  // Screenshot of site-map tab (default)
  await page.screenshot({
    path: "test-results/target-sitemap.png",
    fullPage: true,
  });

  // Switch to scope tab
  await page.getByRole("tab", { name: "Scope" }).click();
  await expect(page.getByTestId("scope-view")).toBeVisible({ timeout: 5000 });

  // Screenshot of scope tab
  await page.screenshot({
    path: "test-results/target-scope.png",
    fullPage: true,
  });

  // Switch to issue-defs tab
  await page.getByRole("tab", { name: "Issue defs" }).click();
  await expect(page.getByTestId("issue-defs-view")).toBeVisible({ timeout: 5000 });

  // Screenshot of issue-defs tab
  await page.screenshot({
    path: "test-results/target-issue-defs.png",
    fullPage: true,
  });
});

test("evidence log page renders chronological list with filters", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/scans/1/evidence");
  await expect(page.getByRole("heading", { name: "Evidence log" })).toBeVisible();

  // Wait for at least one evidence row to appear
  const row = page.getByTestId("evidence-row").first();
  await expect(row).toBeVisible({ timeout: 10000 });

  // Initial screenshot (all filters)
  await page.screenshot({
    path: "test-results/evidence-log.png",
    fullPage: true,
  });

  // Click a row to expand
  await page.getByTestId("evidence-row").first().click();

  // Screenshot with row expanded
  await page.screenshot({
    path: "test-results/evidence-log-expanded.png",
    fullPage: true,
  });
});