import { test, expect } from "@playwright/test";

test("dashboard renders", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  // Take a screenshot for visual verification
  await page.screenshot({
    path: "test-results/dashboard.png",
    fullPage: true,
  });

  // Verify dark mode is applied (html element should have "dark" class)
  const htmlClass = await page.locator("html").getAttribute("class");
  expect(htmlClass).toContain("dark");

  // Verify sidebar nav items are present
  await expect(page.getByRole("link", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Targets" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Scan History" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Plugins" })).toBeVisible();

  // Verify stat cards render
  await expect(page.getByText("Total scans")).toBeVisible();
  await expect(page.getByText("Active targets")).toBeVisible();
  await expect(page.getByText("Findings (7d)")).toBeVisible();

  // Verify mock scans appear
  await expect(page.getByText("staging.example.com")).toBeVisible();
  await expect(page.getByText("api.acme.dev")).toBeVisible();
});

test("plugins page renders with checks", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/plugins");
  await expect(page.getByRole("heading", { name: "Plugins" })).toBeVisible();

  // Wait for at least one check card to render
  const card = page.locator('[data-testid="check-card"]').first();
  await expect(card).toBeVisible({ timeout: 10000 });

  // All 19 backend checks should render
  await expect(page.locator('[data-testid="check-card"]')).toHaveCount(19);

  // Counter should report the total
  await expect(page.getByText(/checks registered/)).toBeVisible();
  await expect(page.getByText("19 checks registered")).toBeVisible();

  // Filter chips exist
  await expect(page.getByRole("button", { name: "All" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Passive" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Low impact" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Active" })).toBeVisible();

  // Click Passive — only passive cards remain
  await page.getByRole("button", { name: "Passive" }).click();
  await expect(page.locator('[data-testid="check-card"]')).not.toHaveCount(19);
  const passiveCount = await page
    .locator('[data-testid="check-card"]')
    .count();
  expect(passiveCount).toBeGreaterThan(0);
  expect(passiveCount).toBeLessThan(19);

  // Click Active — only active cards remain
  await page.getByRole("button", { name: "Active" }).click();
  const activeCount = await page
    .locator('[data-testid="check-card"]')
    .count();
  expect(activeCount).toBeGreaterThan(0);

  // Click All — back to all 19
  await page.getByRole("button", { name: "All" }).click();
  await expect(page.locator('[data-testid="check-card"]')).toHaveCount(19);

  // Screenshot for visual reference
  await page.screenshot({
    path: "test-results/plugins.png",
    fullPage: true,
  });
});