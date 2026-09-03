import { test, expect } from "@playwright/test";

test("probe builder: page renders with mode toggle", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/probe-builder");
  await expect(page.getByRole("heading", { name: "Probe Builder" })).toBeVisible({
    timeout: 10000,
  });
  // Mode tabs
  await expect(page.getByTestId("mode-preset")).toBeVisible();
  await expect(page.getByTestId("mode-custom")).toBeVisible();
  // Target select loads (apiGet /api/targets)
  await expect(page.getByTestId("target-select")).toBeVisible({ timeout: 10000 });
  // Method + position-kind defaults
  await expect(page.getByTestId("method-select")).toBeVisible();
  await expect(page.getByTestId("position-kind-select")).toBeVisible();
  // Initial mode is preset → preset form visible
  await expect(page.getByTestId("preset-set-select")).toBeVisible();
  // No payload → "Continue" button should be disabled
  const cont = page.getByTestId("open-gate1");
  await expect(cont).toBeDisabled();
  await page.screenshot({ path: "test-results/probe-builder.png", fullPage: true });
});

test("probe builder: switch to custom mode shows textarea", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/probe-builder");
  await page.getByTestId("mode-custom").click();
  await expect(page.getByTestId("custom-payloads-input")).toBeVisible({ timeout: 5000 });
  // No payload yet → Continue disabled
  await expect(page.getByTestId("open-gate1")).toBeDisabled();
  // Type a payload → Continue enabled
  await page.getByTestId("custom-payloads-input").fill("test-payload-1\ntest-payload-2");
  await expect(page.getByTestId("open-gate1")).toBeEnabled();
  // Click Continue → Gate 1 (summary) should appear
  await page.getByTestId("open-gate1").click();
  await expect(page.getByTestId("gate1")).toBeVisible({ timeout: 5000 });
  // Gate 2 input appears
  await expect(page.getByTestId("gate2-input")).toBeVisible();
  // Run button only appears once DWYOR phrase matches exactly.
  await expect(page.getByTestId("run-probe")).toHaveCount(0);
  // Type the DWYOR phrase EXACTLY
  await page.getByTestId("gate2-input").fill("I ACKNOWLEDGE DWYOR");
  // Run button appears + is enabled
  await expect(page.getByTestId("run-probe")).toBeVisible({ timeout: 5000 });
  await expect(page.getByTestId("run-probe")).toBeEnabled();
  // Scroll the gates into view so the screenshot shows them clearly
  // without relying on fullPage = true.
  await page.getByTestId("gate1").scrollIntoViewIfNeeded();
  await page.getByTestId("gate2").scrollIntoViewIfNeeded();
  await page.screenshot({ path: "test-results/probe-builder-gates.png", fullPage: true });
});

test("probe builder: wrong DWYOR phrase does not unlock", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/probe-builder");
  await page.getByTestId("mode-custom").click();
  await page.getByTestId("custom-payloads-input").fill("payload-x");
  await page.getByTestId("open-gate1").click();
  await expect(page.getByTestId("gate2-input")).toBeVisible();
  // Wrong phrase — close but not exact
  await page.getByTestId("gate2-input").fill("i acknowledge dwyor");
  // Wrong phrase — Run button should not be visible at all (gated
  // on exact match).
  await expect(page.getByTestId("run-probe")).toHaveCount(0);
});