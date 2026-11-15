/** Whole-app tests: the real <App/> against a mocked network (MSW). */
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "@/App";
import type { ProgressEvent } from "@/lib/api";
import {
  MASKED_AWS,
  MASKED_PASSWORD,
  RAW_AWS,
  RAW_PASSWORD,
  detail,
  finding,
  health,
  overview,
  scan,
  summary,
} from "@/test/fixtures";
import { HttpResponse, http, server } from "@/test/server";

const SLOW = { timeout: 5000 };

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  listeners = new Map<string, Set<(e: MessageEvent<string>) => void>>();
  closed = false;
  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }
  addEventListener(type: string, fn: (e: MessageEvent<string>) => void) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type)?.add(fn);
  }
  removeEventListener(type: string, fn: (e: MessageEvent<string>) => void) {
    this.listeners.get(type)?.delete(fn);
  }
  close() {
    this.closed = true;
  }
  emit(ev: Partial<ProgressEvent> & Pick<ProgressEvent, "stage">) {
    const full: ProgressEvent = { scan_id: 8, current: 0, total: 0, image: "", message: "", ...ev };
    act(() => {
      this.listeners.get("progress")?.forEach((fn) => fn({ data: JSON.stringify(full) } as MessageEvent<string>));
    });
  }
  fail() {
    act(() => {
      this.listeners.get("error")?.forEach((fn) => fn({} as MessageEvent<string>));
    });
  }
}

function open(path: string) {
  window.history.pushState({}, "", path);
  return render(<App />);
}

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  );
  // Radix + jsdom
  Element.prototype.hasPointerCapture = () => false;
  Element.prototype.scrollIntoView = () => undefined;
  window.matchMedia ??= ((q: string) => ({
    matches: false,
    media: q,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
    onchange: null,
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
});
afterEach(() => vi.unstubAllGlobals());

describe("image detail", () => {
  it("groups findings by severity, worst first, with a count per group", async () => {
    server.use(http.get("/api/images/:id", () => HttpResponse.json(detail())));
    open("/images/abc");
    const headings = await screen.findAllByRole("heading", { level: 3 }, SLOW);
    const texts = headings.map((h) => h.textContent ?? "");
    expect(texts).toEqual(["Critical(1)", "High(2)", "Medium(1)", "Low(1)"]);
    // Within a severity every rule is present
    expect(screen.getByText("Container runs as root")).toBeInTheDocument();
    expect(screen.getByText("Image is stale")).toBeInTheDocument();
  });

  it("shows secrets masked in evidence, never the raw value", async () => {
    const user = userEvent.setup();
    open("/images/abc");
    await user.click(await screen.findByRole("button", { name: /Secrets in ENV/ }, SLOW));
    expect(screen.getByText(`AWS_ACCESS_KEY_ID=${MASKED_AWS}`)).toBeInTheDocument();
    expect(screen.getByText(`DB_PASSWORD=${MASKED_PASSWORD}`)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(RAW_AWS);
    expect(document.body.textContent).not.toContain(RAW_PASSWORD);

    await user.click(screen.getByRole("tab", { name: /Config/ }));
    await waitFor(() => expect(document.body.textContent).toContain(`DB_PASSWORD=${MASKED_PASSWORD}`));
    expect(document.body.textContent).not.toContain(RAW_PASSWORD);
    expect(document.body.textContent).not.toContain(RAW_AWS);
  });

  it("renders a hostile finding as text, not markup", async () => {
    const user = userEvent.setup();
    server.use(
      http.get("/api/images/:id", () =>
        HttpResponse.json(
          detail({
            findings: [finding({ title: "<img src=x onerror=alert(1)>", evidence: ["<script>alert(1)</script>"] })],
          }),
        ),
      ),
    );
    const { container } = open("/images/abc");
    await user.click(await screen.findByRole("button", { name: /onerror/ }, SLOW));
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img[src='x']")).toBeNull();
    expect(screen.getByText("<script>alert(1)</script>")).toBeInTheDocument();
  });

  it("explains degraded scanners and that the grade may be optimistic", async () => {
    server.use(
      http.get("/api/images/:id", () =>
        HttpResponse.json(
          detail({
            scanners: [
              { scanner: "filesystem", status: "ok", detail: "" },
              { scanner: "oscap", status: "unsupported", detail: "oscap: image is Alpine Linux, OVAL feed is RHEL only" },
              { scanner: "trivy", status: "unavailable", detail: "trivy not installed" },
            ],
          }),
        ),
      ),
    );
    open("/images/abc");
    expect(await screen.findByText(/could not run during the last scan/i, undefined, SLOW)).toBeInTheDocument();
    expect(screen.getByText(/oscap: image is Alpine Linux/)).toBeInTheDocument();
    expect(screen.getByText(/grade may be optimistic/i)).toBeInTheDocument();
  });

  it("shows an empty findings state for a clean image", async () => {
    server.use(
      http.get("/api/images/:id", () =>
        HttpResponse.json(detail({ findings: [], score: 100, grade: "A", finding_counts: summary().finding_counts })),
      ),
    );
    open("/images/abc");
    expect(await screen.findByText("No findings", undefined, SLOW)).toBeInTheDocument();
  });

  it("shows 'Image not found' for a 404", async () => {
    server.use(http.get("/api/images/:id", () => HttpResponse.json({ detail: "no such image" }, { status: 404 })));
    open("/images/nope");
    expect(await screen.findByText("Image not found", undefined, SLOW)).toBeInTheDocument();
  });

  it("shows the API's message when the server errors, with a retry", async () => {
    const user = userEvent.setup();
    let calls = 0;
    server.use(
      http.get("/api/images/:id", () => {
        calls += 1;
        return calls < 3 ? HttpResponse.json({ detail: "database is locked" }, { status: 500 }) : HttpResponse.json(detail());
      }),
    );
    open("/images/abc");
    expect(await screen.findByText("Could not load this image", undefined, { timeout: 8000 })).toBeInTheDocument();
    expect(screen.getByText("database is locked")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /try again/i }));
    expect(await screen.findByRole("heading", { level: 1, name: /pstest-bad/ }, SLOW)).toBeInTheDocument();
  }, 15000);
});

describe("overview", () => {
  it("shows the fleet numbers", async () => {
    open("/");
    expect(await screen.findByText("Images audited", undefined, SLOW)).toBeInTheDocument();
    expect(screen.getByText("Top 5 riskiest images")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Score 70 out of 100, grade C/ })).toBeInTheDocument();
  });

  it("shows an empty state with a call to action before the first scan", async () => {
    server.use(
      http.get("/api/overview", () =>
        HttpResponse.json(overview({ images_audited: 0, fleet_score: null, fleet_grade: null, riskiest: [], trend: [] })),
      ),
    );
    open("/");
    expect(await screen.findByText("No images audited yet", undefined, SLOW)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /scan all/i }).length).toBeGreaterThan(0);
  });

  it("explains an unreachable server instead of showing a blank page", async () => {
    server.use(http.get("/api/overview", () => HttpResponse.error()));
    open("/");
    expect(await screen.findByText("Could not load the overview", undefined, { timeout: 8000 })).toBeInTheDocument();
    expect(screen.getByText(/Cannot reach the PodShield server/)).toBeInTheDocument();
  }, 15000);
});

describe("unknown routes", () => {
  it("renders the not-found page inside the shell", async () => {
    open("/definitely/not/a/page");
    expect(await screen.findByRole("search", undefined, SLOW)).toBeInTheDocument();
    expect(await screen.findByText("Page not found", undefined, SLOW)).toBeInTheDocument();
  });
});

describe("theme", () => {
  it("defaults to dark, toggles, and persists across a reload", async () => {
    const user = userEvent.setup();
    const first = open("/");
    expect(document.documentElement).toHaveClass("dark");

    await user.click(await screen.findByRole("button", { name: "Switch to light mode" }, SLOW));
    expect(document.documentElement).not.toHaveClass("dark");
    expect(localStorage.getItem("podshield-theme")).toBe("light");

    // "Reload": drop the React tree and the class, keep storage
    first.unmount();
    document.documentElement.classList.add("dark");
    open("/");
    await screen.findByRole("button", { name: "Switch to dark mode" }, SLOW);
    expect(document.documentElement).not.toHaveClass("dark");

    await user.click(screen.getByRole("button", { name: "Switch to dark mode" }));
    expect(document.documentElement).toHaveClass("dark");
    expect(localStorage.getItem("podshield-theme")).toBe("dark");
  });

  it("falls back to dark for a garbage stored value", async () => {
    localStorage.setItem("podshield-theme", "<script>");
    open("/");
    await screen.findByRole("button", { name: "Switch to light mode" }, SLOW);
    expect(document.documentElement).toHaveClass("dark");
  });

  it("still works when storage is blocked", async () => {
    const user = userEvent.setup();
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("denied");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("denied");
    });
    open("/");
    await user.click(await screen.findByRole("button", { name: "Switch to light mode" }, SLOW));
    expect(document.documentElement).not.toHaveClass("dark");
    vi.restoreAllMocks();
  });
});

describe("accessibility", () => {
  it("the top-bar scan button has an accessible name even when its text is hidden on phones", async () => {
    open("/");
    // The visible label is `hidden sm:inline`, so the name must not depend on it.
    const button = await screen.findByRole("button", { name: "Scan all images" }, SLOW);
    expect(button).toHaveAttribute("aria-label", "Scan all images");
  });

  it("icon-only buttons are labelled", async () => {
    open("/");
    await screen.findByText("Images audited", undefined, SLOW);
    for (const button of screen.getAllByRole("button")) {
      const name = button.getAttribute("aria-label") ?? button.textContent?.trim() ?? button.getAttribute("title");
      expect(name, `unlabelled button: ${button.outerHTML.slice(0, 120)}`).toBeTruthy();
    }
  });
});

describe("scan progress", () => {
  it("starts a scan, follows the stream, and finishes", async () => {
    const user = userEvent.setup();
    let body: unknown = null;
    server.use(
      http.post("/api/scans", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ scan_id: 8, status: "queued" }, { status: 202 });
      }),
    );
    open("/");
    await user.click(await screen.findByRole("button", { name: /scan all/i }, SLOW));
    const panel = await screen.findByLabelText("Scan progress", undefined, SLOW);
    expect(body).toEqual({ all: true });
    expect(within(panel).getByText(/Scanning: All images/)).toBeInTheDocument();

    const es = FakeEventSource.instances.at(-1);
    if (!es) throw new Error("no EventSource was opened");
    expect(es.url).toContain("/api/scans/8/");

    es.emit({ stage: "started", message: "all" });
    es.emit({ stage: "image_started", current: 1, total: 2, image: "localhost/a:1" });
    expect(within(panel).getByRole("progressbar")).toHaveAttribute("aria-valuenow", "0");
    es.emit({ stage: "image_done", current: 1, total: 2, image: "localhost/a:1", message: "grade B" });
    expect(within(panel).getByRole("progressbar")).toHaveAttribute("aria-valuenow", "50");
    es.emit({ stage: "completed", current: 2, total: 2 });

    await waitFor(() => expect(within(panel).getByText(/Scan complete: All images/)).toBeInTheDocument());
    expect(within(panel).getByRole("progressbar")).toHaveAttribute("aria-valuenow", "100");
    expect(es.closed).toBe(true);
  });

  it("shows a banner while the connection drops and clears it when events resume", async () => {
    const user = userEvent.setup();
    open("/");
    await user.click(await screen.findByRole("button", { name: /scan all/i }, SLOW));
    const panel = await screen.findByLabelText("Scan progress", undefined, SLOW);
    const es = FakeEventSource.instances.at(-1);
    if (!es) throw new Error("no EventSource was opened");
    es.emit({ stage: "started", message: "all" });

    es.fail();
    expect(within(panel).getByText(/Connection lost, retrying/)).toBeInTheDocument();
    es.emit({ stage: "image_started", current: 1, total: 2, image: "localhost/a:1" });
    expect(within(panel).queryByText(/Connection lost/)).not.toBeInTheDocument();
  });

  it("surfaces a mid-scan Podman failure as a failed scan with the reason", async () => {
    const user = userEvent.setup();
    open("/");
    await user.click(await screen.findByRole("button", { name: /scan all/i }, SLOW));
    const panel = await screen.findByLabelText("Scan progress", undefined, SLOW);
    const es = FakeEventSource.instances.at(-1);
    if (!es) throw new Error("no EventSource was opened");
    es.emit({ stage: "started", message: "all" });
    es.emit({ stage: "failed", message: "Cannot connect to Podman. Is the socket running? systemctl --user start podman.socket" });

    await waitFor(() => expect(within(panel).getByText(/Scan failed: All images/)).toBeInTheDocument());
    expect(within(panel).getAllByText(/Cannot connect to Podman/).length).toBeGreaterThan(0);
    expect(within(panel).getByRole("button", { name: /dismiss/i })).toBeInTheDocument();
    // The scan button is usable again
    expect(screen.getByRole("button", { name: /scan all/i })).toBeEnabled();
  });

  it("reports a scan that cannot be started", async () => {
    const user = userEvent.setup();
    server.use(http.post("/api/scans", () => HttpResponse.json({ detail: "Podman is unavailable" }, { status: 503 })));
    open("/");
    await user.click(await screen.findByRole("button", { name: /scan all/i }, SLOW));
    expect(await screen.findByText("Could not start scan", undefined, SLOW)).toBeInTheDocument();
    expect(screen.getByText("Podman is unavailable")).toBeInTheDocument();
    expect(screen.queryByLabelText("Scan progress")).not.toBeInTheDocument();
  });

  it("re-attaches to a scan that is already running", async () => {
    server.use(http.get("/api/scans", () => HttpResponse.json([scan({ id: 12, status: "running", finished_at: null })])));
    open("/");
    const panel = await screen.findByLabelText("Scan progress", undefined, SLOW);
    expect(within(panel).getByText(/Scan #12/)).toBeInTheDocument();
    expect(FakeEventSource.instances.at(-1)?.url).toContain("/api/scans/12/");
  });
});

describe("health indicator", () => {
  it("counts available scanners and lists the missing one with its reason", async () => {
    const user = userEvent.setup();
    open("/");
    const trigger = await screen.findByRole("button", { name: /Scanner availability: 2\/3 scanners/ }, SLOW);
    await user.click(trigger);
    expect(await screen.findByText(/Unavailable: trivy not found on PATH/)).toBeInTheDocument();
    expect(screen.getByText("Connected")).toBeInTheDocument();
  });

  it("warns, with the fix, when the Podman socket is down", async () => {
    const user = userEvent.setup();
    server.use(http.get("/api/health", () => HttpResponse.json(health({ podman: false }))));
    open("/");
    await user.click(await screen.findByRole("button", { name: /Scanner availability/ }, SLOW));
    expect(await screen.findByText(/systemctl enable --now podman\.socket/)).toBeInTheDocument();
  });

  it("says the API is offline when /api/health cannot be reached", async () => {
    server.use(http.get("/api/health", () => HttpResponse.error()));
    open("/");
    expect(await screen.findByRole("button", { name: "Scanner availability: API offline" }, SLOW)).toBeInTheDocument();
  });
});
