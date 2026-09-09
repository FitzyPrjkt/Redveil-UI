import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:8000";

// Explicit fetch-trace tests for evidence + targets pages that were
// previously "assumed working" via useParams() — verify that they
// actually fetch against the live URL, not the baked "_" placeholder.
test.describe("Explicit usePathname() verification", () => {
  test("/scans/1/evidence fetches /api/scans/1 (not /api/scans/_)", async ({ page }) => {
    const reqs: string[] = [];
    page.on("request", (r) => {
      if (r.url().includes("/api/")) reqs.push(r.url());
    });
    await page.goto(BASE + "/scans/1/evidence", { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(1500);
    const fetched1 = reqs.some((u) => u.includes("/api/scans/1") && !u.includes("/api/scans/1/"));
    const fetchedUnderscore = reqs.some((u) => u.includes("/api/scans/_"));
    expect(fetched1, "must fetch /api/scans/1").toBe(true);
    expect(fetchedUnderscore, "must NOT fetch /api/scans/_").toBe(false);
  });

  test("/targets/1 fetches /api/targets/1 (not /api/targets/_)", async ({ page }) => {
    const reqs: string[] = [];
    page.on("request", (r) => {
      if (r.url().includes("/api/")) reqs.push(r.url());
    });
    await page.goto(BASE + "/targets/1", { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(1500);
    const fetched1 = reqs.some((u) => /\/api\/targets\/1(\?|$)/.test(u) || /\/api\/targets\/1\//.test(u));
    const fetchedUnderscore = reqs.some((u) => u.includes("/api/targets/_"));
    expect(fetched1, "must fetch /api/targets/1 (live URL)").toBe(true);
    expect(fetchedUnderscore, "must NOT fetch /api/targets/_ (placeholder)").toBe(false);
  });

  test("/scans/1 fetches /api/scans/1 (not /api/scans/_)", async ({ page }) => {
    const reqs: string[] = [];
    page.on("request", (r) => {
      if (r.url().includes("/api/")) reqs.push(r.url());
    });
    await page.goto(BASE + "/scans/1", { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(1500);
    const fetched1 = reqs.some((u) => /\/api\/scans\/1(\?|$)/.test(u) || /\/api\/scans\/1\//.test(u));
    const fetchedUnderscore = reqs.some((u) => /\/api\/scans\/_(?!\d)/.test(u) || u.endsWith("/api/scans/_"));
    expect(fetched1, "must fetch /api/scans/1 (live URL)").toBe(true);
    expect(fetchedUnderscore, "must NOT fetch /api/scans/_ (placeholder)").toBe(false);
  });

  test("/findings/WPOC-SEED-001 fetches /api/findings/WPOC-SEED-001 (not /api/findings/_)", async ({ page }) => {
    const reqs: string[] = [];
    page.on("request", (r) => {
      if (r.url().includes("/api/")) reqs.push(r.url());
    });
    await page.goto(BASE + "/findings/WPOC-SEED-001", { waitUntil: "networkidle", timeout: 15000 });
    await page.waitForTimeout(1500);
    const fetchedLive = reqs.some((u) => u.includes("/api/findings/WPOC-SEED-001"));
    const fetchedUnderscore = reqs.some((u) => u.includes("/api/findings/_"));
    expect(fetchedLive, "must fetch /api/findings/WPOC-SEED-001 (live URL)").toBe(true);
    expect(fetchedUnderscore, "must NOT fetch /api/findings/_ (placeholder)").toBe(false);
  });
});
