import { test, expect, Page } from "@playwright/test";

// Base URL via env override (REDVEIL_TEST_BASE) so tests run against
// any port the operator picked during `redveil-ui init`.
const BASE = process.env.REDVEIL_TEST_BASE ?? "http://127.0.0.1:8000";

async function checkPage(page: Page, path: string) {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  const resp = await page.goto(BASE + path, { waitUntil: "networkidle", timeout: 15000 });
  // Wait for client-side hydration to settle (usePathname + API fetch).
  await page.waitForTimeout(2000);
  return { status: resp?.status() ?? 0, errors, body: await page.content() };
}

test.describe("Audit A — functional check (empty DB)", () => {
  test("GET / serves Dashboard with data-testid", async ({ page }) => {
    const r = await checkPage(page, "/");
    expect(r.status).toBe(200);
    // Strict: must render the Dashboard's data-testid wrapper, not just
    // any text that happens to contain "Dashboard".
    expect(r.body, "must render Dashboard").toContain('data-testid="dashboard"');
  });

  test("GET /targets renders Targets list (data-testid=targets-list)", async ({ page }) => {
    const r = await checkPage(page, "/targets");
    expect(r.status).toBe(200);
    expect(r.body, "must render Targets list page").toContain('data-testid="targets-list"');
    expect(r.body, "must NOT render Dashboard").not.toContain('data-testid="dashboard"');
  });

  test("GET /targets/new renders New Target form", async ({ page }) => {
    const r = await checkPage(page, "/targets/new");
    expect(r.status).toBe(200);
    // targets/new has data-testid="new-scan-form"
    expect(r.body).toContain('data-testid="new-scan-form"');
    expect(r.body).not.toContain('data-testid="dashboard"');
  });

  test("GET /scans renders Scan History (data-testid=scan-history)", async ({ page }) => {
    const r = await checkPage(page, "/scans");
    expect(r.status).toBe(200);
    expect(r.body, "must render Scan History page").toContain('data-testid="scan-history"');
    expect(r.body, "must NOT render Dashboard").not.toContain('data-testid="dashboard"');
  });

  test("GET /plugins renders Plugins list (data-testid=checks-grid)", async ({ page }) => {
    const r = await checkPage(page, "/plugins");
    expect(r.status).toBe(200);
    expect(r.body, "must render Plugins grid").toContain('data-testid="checks-grid"');
    expect(r.body).not.toContain('data-testid="dashboard"');
  });

  test("GET /probe-builder renders Probe Builder (data-testid=probe-builder)", async ({ page }) => {
    const r = await checkPage(page, "/probe-builder");
    expect(r.status).toBe(200);
    expect(r.body, "must render Probe Builder page").toContain('data-testid="probe-builder"');
    expect(r.body).not.toContain('data-testid="dashboard"');
  });

  test("GET /settings renders Settings", async ({ page }) => {
    const r = await checkPage(page, "/settings");
    expect(r.status).toBe(200);
    expect(r.body, "must NOT render Dashboard").not.toContain('data-testid="dashboard"');
  });

  test("GET /comparer renders Comparer", async ({ page }) => {
    const r = await checkPage(page, "/comparer");
    expect(r.status).toBe(200);
    expect(r.body, "must NOT render Dashboard").not.toContain('data-testid="dashboard"');
  });

  test("GET /decoder renders Decoder", async ({ page }) => {
    const r = await checkPage(page, "/decoder");
    expect(r.status).toBe(200);
    expect(r.body, "must NOT render Dashboard").not.toContain('data-testid="dashboard"');
  });

  test("GET /tools/token-entropy renders Token Entropy", async ({ page }) => {
    const r = await checkPage(page, "/tools/token-entropy");
    expect(r.status).toBe(200);
    expect(r.body, "must NOT render Dashboard").not.toContain('data-testid="dashboard"');
  });
});

test.describe("Audit A2 dynamic routes (populated DB)", () => {
  test("GET /scans/1 hydrates to scan detail (not dashboard)", async ({ page }) => {
    const r = await checkPage(page, "/scans/1");
    expect(r.status).toBe(200);
    expect(r.body.includes('data-testid="dashboard"'), "/scans/1 should NOT render dashboard after hydration").toBe(false);
  });

  test("GET /scans/1/evidence hydrates to evidence list (not dashboard)", async ({ page }) => {
    const r = await checkPage(page, "/scans/1/evidence");
    expect(r.status).toBe(200);
    expect(r.body.includes('data-testid="dashboard"'), "/scans/1/evidence should NOT render dashboard").toBe(false);
  });

  test("GET /targets/1 hydrates to target sitemap (not dashboard)", async ({ page }) => {
    const r = await checkPage(page, "/targets/1");
    expect(r.status).toBe(200);
    expect(r.body.includes('data-testid="dashboard"'), "/targets/1 should NOT render dashboard").toBe(false);
  });

  test("GET /findings/WPOC-SEED-001 hydrates and shows the finding (not dashboard, not 404)", async ({ page }) => {
    const r = await checkPage(page, "/findings/WPOC-SEED-001");
    expect(r.status).toBe(200);
    expect(r.body.includes('data-testid="dashboard"'), "should NOT render dashboard").toBe(false);
    // Strict: the finding title must appear in the DOM (after hydration
    // + usePathname + API fetch). If this is the placeholder rendering
    // a "Failed to load" error, this assertion will fail.
    await page.waitForSelector("text=Seeded Test Finding", { timeout: 5000 });
  });
});
