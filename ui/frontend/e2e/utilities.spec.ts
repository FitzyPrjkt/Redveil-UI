import { test, expect } from "@playwright/test";

test("decoder page renders and decodes Base64", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/decoder");
  await expect(page.getByRole("heading", { name: "Decoder" })).toBeVisible();
  await expect(page.getByTestId("decoder-input")).toBeVisible();
  await expect(page.getByTestId("decoder-output")).toBeVisible();

  // The page seeds Base64 of "redveilXSSProbe" by default.
  const output = await page.getByTestId("decoder-output").inputValue();
  expect(output).toBe("redveilXSSProbe");

  await page.screenshot({
    path: "test-results/decoder.png",
    fullPage: true,
  });
});

test("comparer page renders diff between two evidence records", async ({
  page,
}) => {
  await page.goto("http://127.0.0.1:3001/comparer?scan_id=1");
  await expect(page.getByRole("heading", { name: "Comparer" })).toBeVisible();
  await expect(page.getByTestId("comparer-left-select")).toBeVisible();
  await expect(page.getByTestId("comparer-right-select")).toBeVisible();

  // Wait for evidence to load and diff to render.
  await expect(page.getByTestId("comparer-diff")).toBeVisible({ timeout: 10000 });

  await page.screenshot({
    path: "test-results/comparer.png",
    fullPage: true,
  });
});

test("token entropy page analyzes a token", async ({ page }) => {
  await page.goto("http://127.0.0.1:3001/tools/token-entropy");
  await expect(page.getByRole("heading", { name: "Token entropy" })).toBeVisible();
  await expect(page.getByTestId("entropy-input")).toBeVisible();

  // Click analyze — replace the seeded value with 12 identical chars so
  // the entropy math lands cleanly in the "weak" range.
  await page.getByTestId("entropy-input").click();
  await page.getByTestId("entropy-input").press("ControlOrMeta+a");
  await page.getByTestId("entropy-input").press("Delete");
  await page.getByTestId("entropy-input").type("aaaaaaaaaaaa");
  await page.getByTestId("entropy-submit").click();

  await expect(page.getByTestId("entropy-result")).toBeVisible({ timeout: 10000 });
  await expect(page.getByTestId("entropy-bits")).toContainText("0");
  await expect(page.getByTestId("entropy-length")).toContainText("12");

  await page.screenshot({
    path: "test-results/token-entropy.png",
    fullPage: true,
  });
});