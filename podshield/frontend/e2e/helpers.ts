import { type APIRequestContext, type Page, expect } from "@playwright/test";

export const PAGES = [
  { slug: "overview", path: "/", heading: "Overview" },
  { slug: "images", path: "/images", heading: "Images" },
  { slug: "containers", path: "/containers", heading: "Containers" },
  { slug: "registry", path: "/registry", heading: "Registry Scan" },
  { slug: "history", path: "/history", heading: "Scan History" },
  { slug: "rules", path: "/rules", heading: "Rules" },
  { slug: "settings", path: "/settings", heading: "Settings" },
] as const;

export const VIEWPORTS = [
  { name: "mobile", width: 375, height: 812 },
  { name: "tablet", width: 768, height: 1024 },
  { name: "desktop", width: 1440, height: 900 },
] as const;

/** The control endpoint only exists on the demo server; on a real install this is false. */
export async function chaosAvailable(request: APIRequestContext): Promise<boolean> {
  const res = await request.post("/__e2e/chaos", { data: {} });
  return res.ok();
}

export async function chaos(request: APIRequestContext, state: { podman?: boolean; filesystem?: boolean; delay?: number }) {
  const res = await request.post("/__e2e/chaos", { data: state });
  expect(res.ok()).toBeTruthy();
}

export async function resetChaos(request: APIRequestContext) {
  if (await chaosAvailable(request)) await chaos(request, { podman: true, filesystem: true, delay: 0 });
}

/** Run a full scan through the API and wait for it, so pages have data to show. */
export async function seedScan(request: APIRequestContext): Promise<number> {
  const res = await request.post("/api/scans", { data: { all: true } });
  expect(res.status()).toBe(202);
  const { scan_id: id } = (await res.json()) as { scan_id: number };
  await expect
    .poll(
      async () => ((await (await request.get(`/api/scans/${id}`)).json()) as { status: string }).status,
      { timeout: 90_000, intervals: [500] },
    )
    .toMatch(/completed|failed/);
  return id;
}

/** Worst-scoring image id: the API returns riskiest first. */
export async function riskiestImageId(request: APIRequestContext): Promise<string> {
  const images = (await (await request.get("/api/images")).json()) as { id: string }[];
  expect(images.length).toBeGreaterThan(0);
  return images[0].id;
}

/** Fail the test on uncaught exceptions and console errors (ignoring intentionally failing requests). */
export function watchForErrors(page: Page, allow: RegExp[] = []): string[] {
  const problems: string[] = [];
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const text = m.text();
    if (allow.some((re) => re.test(text))) return;
    problems.push(`console.error: ${text}`);
  });
  return problems;
}

export async function waitForSettled(page: Page) {
  await page.waitForLoadState("networkidle");
  // Skeletons mean data is still loading.
  await expect(page.locator(".animate-pulse")).toHaveCount(0, { timeout: 15_000 }).catch(() => undefined);
  // Let chart/ring entrance animations finish so screenshots are stable.
  await page.waitForTimeout(1100);
}

export async function setTheme(page: Page, theme: "dark" | "light") {
  await page.addInitScript((t) => localStorage.setItem("podshield-theme", t), theme);
}

export async function noHorizontalOverflow(page: Page) {
  const report = await page.evaluate(() => {
    const doc = document.documentElement;
    const overflow = doc.scrollWidth - doc.clientWidth;
    const culprits =
      overflow > 1
        ? [...document.querySelectorAll<HTMLElement>("body *")]
            .filter((el) => el.getBoundingClientRect().right > doc.clientWidth + 1)
            .slice(0, 5)
            .map((el) => `${el.tagName.toLowerCase()}.${String(el.className).slice(0, 60)}`)
        : [];
    return { overflow, culprits };
  });
  expect(report.overflow, `${page.url()} scrolls horizontally; widest: ${report.culprits.join(" | ")}`).toBeLessThanOrEqual(1);
}
