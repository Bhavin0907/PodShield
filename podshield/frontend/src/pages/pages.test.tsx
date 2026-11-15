import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TooltipProvider } from "@/components/ui/tooltip";
import { ScanProvider } from "@/lib/scan-context";
import type { ImageSummary, Rule } from "@/lib/api";
import ImagesPage, { filterImages } from "@/pages/images";
import RulesPage, { isOverridden } from "@/pages/rules";

const counts = (o: Partial<Record<string, number>> = {}) => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0, ...o });

const image = (over: Partial<ImageSummary>): ImageSummary => ({
  id: "aaaa1111",
  short_id: "aaaa1111",
  name: "localhost/demo-bad:latest",
  repo_tags: ["localhost/demo-bad:latest"],
  registry: "localhost",
  size: 500_000_000,
  created: "2026-01-01T00:00:00Z",
  age_days: 300,
  score: 40,
  grade: "F",
  last_scanned_at: "2026-11-15T10:00:00Z",
  finding_counts: counts({ critical: 1, high: 2 }),
  cve_counts: counts(),
  cve_total: 0,
  ...over,
});

const IMAGES: ImageSummary[] = [
  image({}),
  image({
    id: "bbbb2222",
    short_id: "bbbb2222",
    name: "registry.access.redhat.com/ubi9/ubi-minimal:9.4",
    repo_tags: ["registry.access.redhat.com/ubi9/ubi-minimal:9.4"],
    registry: "registry.access.redhat.com",
    score: 100,
    grade: "A",
    finding_counts: counts(),
  }),
];

const RULES: Rule[] = [
  { id: "PS-001", title: "Container runs as root", description: "d", kind: "image", default_severity: "high", severity: "high", enabled: true },
  { id: "PS-R01", title: "Privileged container", description: "d", kind: "runtime", default_severity: "critical", severity: "critical", enabled: true },
];

function mockFetch(routes: Record<string, (init?: RequestInit) => unknown>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      const key = Object.keys(routes).find((k) => url.startsWith(k));
      if (!key) return new Response(JSON.stringify({ detail: "nope" }), { status: 404 });
      return new Response(JSON.stringify(routes[key](init)), { status: 200 });
    }),
  );
  return calls;
}

function LocationProbe() {
  const loc = useLocation();
  return <div data-testid="location">{loc.pathname + loc.search}</div>;
}

function renderAt(path: string, ui: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <MemoryRouter initialEntries={[path]}>
          <ScanProvider>
            <Routes>
              <Route path="/images" element={ui} />
              <Route path="/rules" element={ui} />
              <Route path="/images/:id" element={<div>detail page</div>} />
            </Routes>
            <LocationProbe />
          </ScanProvider>
        </MemoryRouter>
      </TooltipProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  // Radix Select needs these in jsdom
  Element.prototype.hasPointerCapture = () => false;
  Element.prototype.scrollIntoView = () => undefined;
});
afterEach(() => vi.unstubAllGlobals());

describe("filterImages", () => {
  const all = { q: "", grade: "all", severity: "all", registry: "all" };
  it("filters by text, grade, severity and registry", () => {
    expect(filterImages(IMAGES, all)).toHaveLength(2);
    expect(filterImages(IMAGES, { ...all, q: "UBI" })).toHaveLength(1);
    expect(filterImages(IMAGES, { ...all, q: "bbbb" })).toHaveLength(1);
    expect(filterImages(IMAGES, { ...all, grade: "F" })[0].short_id).toBe("aaaa1111");
    expect(filterImages(IMAGES, { ...all, severity: "critical" })).toHaveLength(1);
    expect(filterImages(IMAGES, { ...all, registry: "localhost" })).toHaveLength(1);
    expect(filterImages(IMAGES, { ...all, q: "zzz" })).toHaveLength(0);
  });
});

describe("ImagesPage", () => {
  it("lists images, worst first, and honours ?q= from the global search", async () => {
    mockFetch({ "/api/images": () => IMAGES });
    renderAt("/images", <ImagesPage />);
    const rows = await screen.findAllByRole("row");
    // header + 2 rows, lowest score first by default
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText("localhost/demo-bad:latest")).toBeInTheDocument();
    expect(screen.getByText("2 of 2 images")).toBeInTheDocument();
  });

  it("filters from the URL and clears", async () => {
    const user = userEvent.setup();
    mockFetch({ "/api/images": () => IMAGES });
    renderAt("/images?q=ubi", <ImagesPage />);
    await screen.findByText("1 of 2 images");
    expect(screen.queryByText("localhost/demo-bad:latest")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /clear/i }));
    await screen.findByText("2 of 2 images");
    expect(screen.getByTestId("location")).toHaveTextContent("/images");
  });

  it("opens the detail page when a row is clicked", async () => {
    const user = userEvent.setup();
    mockFetch({ "/api/images": () => IMAGES });
    renderAt("/images", <ImagesPage />);
    await user.click(await screen.findByLabelText("Open localhost/demo-bad:latest"));
    expect(await screen.findByText("detail page")).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/images/aaaa1111");
  });

  it("shows an empty state with a call to action", async () => {
    mockFetch({ "/api/images": () => [] });
    renderAt("/images", <ImagesPage />);
    expect(await screen.findByText("No scanned images")).toBeInTheDocument();
  });

  it("shows a helpful error when the API is down", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("fetch failed"))));
    renderAt("/images", <ImagesPage />);
    expect(await screen.findByText("Could not load images")).toBeInTheDocument();
    expect(screen.getByText(/Cannot reach the PodShield server/)).toBeInTheDocument();
  });
});

describe("RulesPage", () => {
  it("groups rules and PATCHes the toggle", async () => {
    const user = userEvent.setup();
    const calls = mockFetch({
      "/api/rules/PS-001": (init) => ({ ...RULES[0], enabled: JSON.parse(String(init?.body)).enabled }),
      "/api/rules": () => RULES,
    });
    renderAt("/rules", <RulesPage />);
    expect(await screen.findByText("Image hygiene")).toBeInTheDocument();
    expect(screen.getByText("Runtime")).toBeInTheDocument();

    await user.click(screen.getByRole("switch", { name: "Disable PS-001" }));
    await waitFor(() => expect(screen.getByRole("switch", { name: "Enable PS-001" })).toBeInTheDocument());

    const patch = calls.find((c) => c.init?.method === "PATCH");
    expect(patch?.url).toBe("/api/rules/PS-001");
    expect(JSON.parse(String(patch?.init?.body))).toEqual({ enabled: false });
    expect(screen.getByText("Customized")).toBeInTheDocument();
  });

  it("detects customised rules", () => {
    expect(isOverridden(RULES[0])).toBe(false);
    expect(isOverridden({ ...RULES[0], enabled: false })).toBe(true);
    expect(isOverridden({ ...RULES[0], severity: "low" })).toBe(true);
  });
});
