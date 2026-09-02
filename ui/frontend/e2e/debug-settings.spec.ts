import { test } from "@playwright/test";

test("settings: capture network + console errors", async ({ page }) => {
  const apiCalls: { url: string; status: number; body: string }[] = [];
  const consoleErrors: string[] = [];

  page.on("response", async (resp) => {
    if (resp.url().includes("/api/")) {
      try {
        const body = await resp.text();
        apiCalls.push({ url: resp.url(), status: resp.status(), body: body.slice(0, 300) });
      } catch {
        apiCalls.push({ url: resp.url(), status: resp.status(), body: "(no body)" });
      }
    }
  });
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => consoleErrors.push("PAGE: " + err.message));

  await page.goto("http://127.0.0.1:3001/settings", { waitUntil: "networkidle" });
  await page.waitForTimeout(2000);

  console.log("=== API calls ===");
  for (const c of apiCalls) console.log(`${c.status} ${c.url}\n  body: ${c.body}`);
  console.log("=== Console errors ===");
  for (const e of consoleErrors) console.log(e);
  console.log("=== Page content snippet ===");
  const text = await page.textContent("body");
  console.log(text?.slice(0, 1500));
});
