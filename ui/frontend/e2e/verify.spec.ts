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

  // Verify the activity list shows the real seeded target URL
  // (no more hardcoded mock "staging.example.com" / "api.acme.dev"
  // — those were placeholders from before Dashboard was wired).
  await expect(
    page.getByTestId("activity-row").first(),
  ).toBeVisible({ timeout: 10000 });
  // The seeded DB has a staging-app target; the real data must show it.
  // Many scans hit the same target so use .first() to avoid
  // strict-mode violation.
  await expect(page.getByText("staging.example.com").first()).toBeVisible();
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

test("new scan form renders all destructive-level fields", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/targets/new");
  await expect(page.getByRole("heading", { name: "New Scan" })).toBeVisible();

  // URL field is required and present
  await expect(page.getByTestId("scan-url")).toBeVisible();

  // Profile radio group has all three options
  await expect(page.getByTestId("scan-url")).toBeVisible();
  await expect(page.getByText("passive", { exact: true })).toBeVisible();
  await expect(page.getByText("low_impact", { exact: true })).toBeVisible();
  await expect(page.getByText("active", { exact: true })).toBeVisible();

  // Destructive level dropdown is present with default L2
  const levelSelect = page.getByTestId("scan-level");
  await expect(levelSelect).toBeVisible();
  await expect(levelSelect).toHaveValue("L2");

  // Allow destructive checkbox is unchecked by default
  const allowDestructive = page.getByTestId("scan-allow-destructive");
  await expect(allowDestructive).toBeVisible();
  await expect(allowDestructive).not.toBeChecked();

  // No destructive warning is shown by default
  await expect(
    page.getByText("Findings pada level ini"),
  ).not.toBeVisible();

  // Gate mode dropdown defaults to non_interactive
  const gateSelect = page.getByTestId("scan-gate-mode");
  await expect(gateSelect).toBeVisible();
  await expect(gateSelect).toHaveValue("non_interactive");

  // Max requests input is present
  await expect(page.getByTestId("scan-max-requests")).toBeVisible();

  // Toggling allow destructive reveals the warning
  await allowDestructive.check();
  await expect(
    page.getByText("Findings pada level ini"),
  ).toBeVisible();

  // Screenshot for visual reference
  await page.screenshot({
    path: "test-results/new-scan.png",
    fullPage: true,
  });
});