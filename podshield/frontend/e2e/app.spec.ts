import { expect, test } from "@playwright/test";

import {
  PAGES,
  VIEWPORTS,
  chaos,
  chaosAvailable,
  noHorizontalOverflow,
  resetChaos,
  riskiestImageId,
  seedScan,
  waitForSettled,
  watchForErrors,
} from "./helpers";

test.beforeAll(async ({ request }) => {
  await resetChaos(request);
  await seedScan(request);
});
test.afterEach(async ({ request }) => resetChaos(request));

test.describe("every page", () => {
  for (const p of PAGES) {
    test(`${p.slug} renders without errors`, async ({ page }) => {
      const problems = watchForErrors(page);
      await page.goto(p.path);
      await expect(page.getByRole("heading", { level: 1, name: p.heading })).toBeVisible();
      await waitForSettled(page);
      expect(problems).toEqual([]);
    });
  }

  test("image detail renders without errors", async ({ page, request }) => {
    const problems = watchForErrors(page);
    await page.goto(`/images/${await riskiestImageId(request)}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.getByRole("tab", { name: /Findings/ })).toBeVisible();
    await waitForSettled(page);
    expect(problems).toEqual([]);
  });

  test("unknown routes show the not-found page inside the shell", async ({ page }) => {
    await page.goto("/no/such/page");
    await expect(page.getByText("Page not found")).toBeVisible();
    await expect(page.getByRole("link", { name: "Overview" }).first()).toBeVisible();
  });

  test("the SPA serves deep links after a hard reload", async ({ page }) => {
    await page.goto("/rules");
    await page.reload();
    await expect(page.getByRole("heading", { level: 1, name: "Rules" })).toBeVisible();
  });
});

test.describe("navigation", () => {
  test("sidebar links reach every page", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/");
    const nav = page.getByRole("navigation");
    for (const p of PAGES.filter((x) => x.path !== "/")) {
      await nav.getByRole("link", { name: p.heading.replace(" Scan", ""), exact: false }).first().click();
      await expect(page).toHaveURL(new RegExp(`${p.path}$`));
      await expect(page.getByRole("heading", { level: 1, name: p.heading })).toBeVisible();
    }
  });

  test("global search filters images and '/' focuses it", async ({ page }) => {
    await page.goto("/");
    await page.keyboard.press("/");
    await expect(page.getByLabel("Search images")).toBeFocused();
    await page.keyboard.type("zzz-no-such-image");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/images\?q=zzz-no-such-image/);
    await expect(page.getByText("No images match")).toBeVisible();
  });

  test("clicking an image row opens its audit", async ({ page }) => {
    await page.goto("/images");
    await waitForSettled(page);
    await page.getByRole("row").nth(1).click();
    await expect(page).toHaveURL(/\/images\/.+/);
    await expect(page.getByRole("tab", { name: /Findings/ })).toBeVisible();
  });
});

test.describe("theme", () => {
  test("toggle persists across reloads and sets the class", async ({ page }) => {
    await page.goto("/");
    const html = page.locator("html");
    await expect(html).toHaveClass(/dark/);
    await page.getByRole("button", { name: "Switch to light mode" }).click();
    await expect(html).not.toHaveClass(/dark/);
    await page.reload();
    await expect(html).not.toHaveClass(/dark/);
    await expect(page.getByRole("button", { name: "Switch to dark mode" })).toBeVisible();
    await page.getByRole("button", { name: "Switch to dark mode" }).click();
    await page.reload();
    await expect(html).toHaveClass(/dark/);
  });

  test("the Settings page controls the same preference", async ({ page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: /light/i }).first().click();
    await expect(page.locator("html")).not.toHaveClass(/dark/);
    await page.goto("/");
    await expect(page.locator("html")).not.toHaveClass(/dark/);
  });
});

test.describe("responsive layout", () => {
  for (const vp of VIEWPORTS) {
    test(`${vp.name} (${vp.width}px): no horizontal scroll on any page`, async ({ page, request }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height });
      const detail = `/images/${await riskiestImageId(request)}`;
      for (const path of [...PAGES.map((p) => p.path), detail]) {
        await page.goto(path);
        await waitForSettled(page);
        await noHorizontalOverflow(page);
      }
    });
  }

  test("375px: navigation collapses behind a menu button", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto("/");
    const menu = page.getByRole("button", { name: "Open navigation" });
    await expect(menu).toBeVisible();
    await menu.click();
    await page.getByRole("link", { name: "Images" }).first().click();
    await expect(page).toHaveURL(/\/images$/);
    await expect(page.getByRole("heading", { level: 1, name: "Images" })).toBeVisible(); // drawer closed itself
  });

  test("1440px: the sidebar is persistent and can collapse", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/");
    await expect(page.getByRole("button", { name: "Open navigation" })).toBeHidden();
    await page.getByRole("button", { name: "Collapse sidebar" }).click();
    await expect(page.getByRole("button", { name: "Expand sidebar" })).toBeVisible();
    await page.reload();
    await expect(page.getByRole("button", { name: "Expand sidebar" })).toBeVisible(); // remembered
  });

  test("the scan progress panel never overflows a phone", async ({ page, request }) => {
    test.skip(!(await chaosAvailable(request)), "needs the demo server to slow the scan down");
    await chaos(request, { delay: 1 });
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto("/");
    await page.getByRole("button", { name: /scan all|scanning/i }).click();
    const panel = page.getByLabel("Scan progress");
    await expect(panel).toBeVisible();
    const box = await panel.boundingBox();
    expect(box).not.toBeNull();
    expect((box?.x ?? -1) >= 0 && (box?.x ?? 0) + (box?.width ?? 0) <= 375).toBeTruthy();
    await expect(panel.getByText(/Scan complete: All images/)).toBeVisible({ timeout: 60_000 });
  });
});

test.describe("scanning from the UI", () => {
  test("Scan all shows live progress, then fresh results", async ({ page, request }) => {
    test.skip(!(await chaosAvailable(request)), "needs the demo server to slow the scan down");
    await chaos(request, { delay: 0.6 });
    await page.goto("/");
    await page.getByRole("button", { name: /scan all/i }).click();
    const panel = page.getByLabel("Scan progress");
    await expect(panel.getByText(/Scanning: All images/)).toBeVisible();
    await expect(panel.getByRole("progressbar")).toBeVisible();
    await expect(panel.getByText(/Scan complete: All images/)).toBeVisible({ timeout: 60_000 });
    await expect(panel.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "100");
    await page.getByRole("button", { name: "Dismiss scan progress" }).click();
    await expect(panel).toBeHidden();
  });

  test("the Scan button is disabled while a scan runs", async ({ page, request }) => {
    test.skip(!(await chaosAvailable(request)), "needs the demo server to slow the scan down");
    await chaos(request, { delay: 1 });
    await page.goto("/");
    const button = page.getByRole("button", { name: /scan all|scanning/i });
    await button.click();
    await expect(page.getByRole("button", { name: /scanning/i })).toBeDisabled();
    await expect(page.getByLabel("Scan progress").getByText(/Scan complete: All images/)).toBeVisible({ timeout: 60_000 });
    await expect(page.getByRole("button", { name: /scan all/i })).toBeEnabled();
  });
});

test.describe("when things break", () => {
  test.beforeEach(async ({ request }) => {
    test.skip(!(await chaosAvailable(request)), "needs the demo server's control endpoint");
  });

  test("a stopped Podman socket fails the scan with the fix, not a blank screen", async ({ page, request }) => {
    await chaos(request, { podman: false });
    await page.goto("/");
    await page.getByRole("button", { name: /scan all/i }).click();
    const panel = page.getByLabel("Scan progress");
    await expect(panel.getByText(/Scan failed: All images/)).toBeVisible();
    await expect(panel.getByText(/Cannot connect to Podman/).first()).toBeVisible();
    await expect(panel.getByText(/podman\.socket/).first()).toBeVisible();
    // The UI recovers: the scan button works again
    await expect(page.getByRole("button", { name: /scan all/i })).toBeEnabled();
  });

  test("the scanner indicator turns red and explains how to restart the socket", async ({ page, request }) => {
    await chaos(request, { podman: false });
    await page.goto("/");
    await page.getByRole("button", { name: /Scanner availability/ }).click();
    await expect(page.getByText(/systemctl enable --now podman\.socket/)).toBeVisible();
  });

  test("a scanner failing mid-scan is reported on the image, and the scan still finishes", async ({ page, request }) => {
    await chaos(request, { filesystem: false });
    const id = await seedScan(request);
    expect(id).toBeGreaterThan(0);
    await page.goto(`/images/${await riskiestImageId(request)}`);
    await expect(page.getByText(/could not run during the last scan/i)).toBeVisible();
    await expect(page.getByText(/podman socket closed while mounting/i)).toBeVisible();
    await expect(page.getByText(/grade may be optimistic/i)).toBeVisible();
  });

  test("the API going away shows an error with Retry, then recovers", async ({ page }) => {
    let down = true;
    await page.route("**/api/overview", (route) => (down ? route.abort("connectionrefused") : route.continue()));
    await page.goto("/");
    await expect(page.getByText("Could not load the overview")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText(/Cannot reach the PodShield server/)).toBeVisible();
    down = false;
    await page.getByRole("button", { name: /try again/i }).click();
    await expect(page.getByText("Could not load the overview")).toBeHidden();
  });
});

test.describe("secrets", () => {
  test("no page shows an unmasked secret", async ({ page, request }) => {
    const raw = ["AKIAIOSFODNN7EXAMPLE", "hunter2-super-secret"];
    const id = await riskiestImageId(request);
    for (const path of ["/", "/images", `/images/${id}`]) {
      await page.goto(path);
      await waitForSettled(page);
      if (path.includes("/images/")) {
        await page.getByRole("tab", { name: "Config" }).click();
      }
      const text = await page.locator("body").innerText();
      for (const secret of raw) expect(text, `${path} leaked ${secret}`).not.toContain(secret);
    }
  });

  test("masked secrets show as 4 characters then ****", async ({ page, request }) => {
    test.skip(!(await chaosAvailable(request)), "needs the demo server's known fixtures");
    await page.goto(`/images/${await riskiestImageId(request)}`);
    await page.getByRole("button", { name: /secret/i }).first().click();
    await expect(page.locator("body")).toContainText(/\w{4}\*{4}/);
  });
});
