/* Verify Probe Builder actually calls the backend API, not just renders.

Run a probe end-to-end with both gate confirmations and assert the
POST /api/probes/custom endpoint is hit + a probe_id is returned.
*/
import { test, expect, type Page } from "@playwright/test";

const BASE = "http://127.0.0.1:3001";
const DWYOR = "I ACKNOWLEDGE DWYOR";

async function captureApi(page: Page) {
  const calls: Array<{ method: string; url: string; status: number }> = [];
  page.on("response", async (resp) => {
    if (resp.url().includes("/api/")) {
      calls.push({
        method: resp.request().method(),
        url: resp.url().replace(BASE, ""),
        status: resp.status(),
      });
    }
  });
  return calls;
}

test("probe builder: preset mode loads payload-sets + run POSTs to /api/probes/custom", async ({
  page,
}) => {
  const calls = await captureApi(page);
  await page.goto(`${BASE}/probe-builder`);
  // Wait for target select to populate (proves /api/targets hit)
  await expect(page.getByTestId("target-select")).toBeVisible({ timeout: 5000 });
  await page.waitForTimeout(500); // allow payload-sets fetch

  // Preset mode is default; type the DWYOR phrase
  await page.getByTestId("preset-indices-input").fill("0,1");
  await page.getByTestId("open-gate1").click();
  await expect(page.getByTestId("gate1")).toBeVisible();
  await page.getByTestId("gate2-input").fill(DWYOR);
  await expect(page.getByTestId("run-probe")).toBeEnabled();

  // Run probe — expect POST to /api/probes/custom + a probe_id result
  await page.getByTestId("run-probe").click();
  await expect(page.getByText(/PRB-/)).toBeVisible({ timeout: 10000 });

  // Verify the actual API call happened
  const postCalls = calls.filter(
    (c) => c.method === "POST" && c.url.endsWith("/api/probes/custom"),
  );
  expect(postCalls.length).toBeGreaterThanOrEqual(1);
  expect(postCalls[0].status).toBeLessThan(500); // 200 OK, 422 missing recipe, etc.

  // Verify the GET calls for target + payload sets
  const getTargets = calls.filter(
    (c) => c.method === "GET" && c.url.endsWith("/api/targets"),
  );
  expect(getTargets.length).toBeGreaterThanOrEqual(1);
  const getPayloadSets = calls.filter(
    (c) => c.method === "GET" && c.url.endsWith("/api/probes/payload-sets"),
  );
  expect(getPayloadSets.length).toBeGreaterThanOrEqual(1);
});

test("probe builder: 403 returned when confirmed_dwyor is missing (server gate)", async ({
  page,
}) => {
  const calls = await captureApi(page);
  // Direct API call bypassing the client two-gate flow
  const resp = await page.request.post(`http://127.0.0.1:8000/api/probes/custom`, {
    headers: { "Content-Type": "application/json" },
    data: {
      target_id: 1,
      payloads: ["test1"],
      method: "GET",
      position: "q",
      position_kind: "query",
      confirmed_dwyor: false,
    },
  });
  expect(resp.status()).toBe(403);
  const body = await resp.json();
  expect(body.detail).toContain("confirmed_dwyor");
});
