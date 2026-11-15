import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";

import { PAGES, VIEWPORTS, resetChaos, riskiestImageId, seedScan, setTheme, waitForSettled } from "./helpers";

/** Every page, both themes, desktop plus a phone, written to docs/screenshots/. */
const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = process.env.SCREENSHOT_DIR ?? path.resolve(here, "../../docs/screenshots");

test.beforeAll(async ({ request }) => {
  await resetChaos(request);
  await seedScan(request);
});

for (const theme of ["dark", "light"] as const) {
  for (const vp of VIEWPORTS.filter((v) => v.name !== "tablet")) {
    test(`screenshots: ${theme} ${vp.name}`, async ({ page, request }) => {
      test.setTimeout(120_000);
      await setTheme(page, theme);
      await page.setViewportSize({ width: vp.width, height: vp.height });
      const targets = [...PAGES.map((p) => ({ slug: p.slug, path: p.path })), { slug: "image-detail", path: `/images/${await riskiestImageId(request)}` }];
      for (const t of targets) {
        await page.goto(t.path);
        await waitForSettled(page);
        const dark = await page.locator("html").evaluate((el) => el.classList.contains("dark"));
        expect(dark).toBe(theme === "dark");
        await page.screenshot({ path: path.join(OUT, `${theme}-${vp.name}-${t.slug}.png`), fullPage: true });
      }
    });
  }
}
