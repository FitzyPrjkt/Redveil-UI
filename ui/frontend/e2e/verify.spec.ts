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