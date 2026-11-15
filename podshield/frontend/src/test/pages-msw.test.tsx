/** Containers, History, Registry, Settings, CVE table and Layers, against a mocked network. */
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import App from "@/App";
import { LayersView } from "@/components/layers-view";
import { VulnsTable } from "@/components/vulns-table";
import type { Container, Layer, RegistryResult, Vulnerability } from "@/lib/api";
import { detail, finding, scan } from "@/test/fixtures";
import { HttpResponse, http, server } from "@/test/server";

const SLOW = { timeout: 5000 };

function open(path: string) {
  window.history.pushState({}, "", path);
  return render(<App />);
}

beforeEach(() => {
  vi.stubGlobal("EventSource", class { addEventListener() {} removeEventListener() {} close() {} });
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  Element.prototype.hasPointerCapture = () => false;
  Element.prototype.scrollIntoView = () => undefined;
});

const container = (over: Partial<Container> = {}): Container => ({
  id: "c".repeat(64),
  short_id: "cccccccccccc",
  name: "pstest-web",
  image: "localhost/pstest-bad:latest",
  status: "running",
  score: 55,
  grade: "D",
  findings: [finding({ rule_id: "PS-R01", severity: "critical", title: "Privileged container" })],
  ...over,
});

describe("containers page", () => {
  it("lists running containers with their runtime findings", async () => {
    const user = userEvent.setup();
    server.use(
      http.get("/api/containers", () =>
        HttpResponse.json([container(), container({ id: "d".repeat(64), name: "pstest-clean", findings: [], score: 100, grade: "A" })]),
      ),
    );
    open("/containers");
    expect(await screen.findByText("pstest-web", undefined, SLOW)).toBeInTheDocument();
    expect(screen.getByText("No runtime issues found")).toBeInTheDocument();
    expect(screen.getByText("1 critical")).toBeInTheDocument();
    expect(screen.getByText(/2 running containers/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Privileged container/ }));
    expect(screen.getByText("No USER instruction.")).toBeInTheDocument();
  });

  it("shows an empty state when nothing is running", async () => {
    open("/containers");
    expect(await screen.findByText("No running containers", undefined, SLOW)).toBeInTheDocument();
  });

  it("explains a 503 as Podman being unreachable", async () => {
    server.use(http.get("/api/containers", () => HttpResponse.json({ detail: "Podman socket unreachable" }, { status: 503 })));
    open("/containers");
    expect(await screen.findByText("Podman is not reachable", undefined, SLOW)).toBeInTheDocument();
    expect(screen.getByText("Podman socket unreachable")).toBeInTheDocument();
  });

  it("shows a generic error for other failures", async () => {
    server.use(http.get("/api/containers", () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    open("/containers");
    expect(await screen.findByText("Could not load containers", undefined, SLOW)).toBeInTheDocument();
  });
});

describe("history page", () => {
  it("shows an empty state before any scan", async () => {
    server.use(http.get("/api/scans", () => HttpResponse.json([])));
    open("/history");
    expect(await screen.findByText("No scans yet", undefined, SLOW)).toBeInTheDocument();
  });

  it("lists scans and reveals the failure reason and scanner states on expand", async () => {
    const user = userEvent.setup();
    server.use(
      http.get("/api/scans", () =>
        HttpResponse.json([
          scan({ id: 9, status: "failed", error: "Cannot connect to Podman", images_scanned: 0 }),
          scan({ id: 8 }),
        ]),
      ),
      http.get("/api/scans/:id", ({ params }) =>
        HttpResponse.json({
          ...scan({ id: Number(params.id), status: "failed", error: "Cannot connect to Podman", images_scanned: 0 }),
          scanners: [
            { scanner: "oscap", status: "unsupported", detail: "image is Alpine, feed is RHEL" },
            { scanner: "trivy", status: "ok", detail: "" },
          ],
        }),
      ),
    );
    open("/history");
    expect(await screen.findByText("Scan #9", { exact: false }, SLOW)).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.getByText("Completed")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Scan #9/ }));
    expect(await screen.findByText("Cannot connect to Podman", undefined, SLOW)).toBeInTheDocument();
    expect(screen.getByText(/OpenSCAP \(OVAL\): unsupported/)).toBeInTheDocument();
    expect(screen.getByText(/image is Alpine, feed is RHEL/)).toBeInTheDocument();
  });

  it("shows an error with retry when the API fails", async () => {
    server.use(http.get("/api/scans", () => HttpResponse.json({ detail: "db is locked" }, { status: 500 })));
    open("/history");
    expect(await screen.findByText("Could not load scan history", undefined, { timeout: 8000 })).toBeInTheDocument();
  }, 15000);
});

describe("registry page", () => {
  const result = (over: Partial<RegistryResult> = {}): RegistryResult => ({
    reference: "quay.io/example/app:1.0",
    id: "sha256:" + "e".repeat(64),
    score: 82,
    grade: "B",
    size: 50_000_000,
    created: "2026-01-01T00:00:00Z",
    findings: [finding({ rule_id: "PS-011", severity: "low", title: "No HEALTHCHECK" })],
    skipped_rules: ["PS-004", "PS-010"],
    notes: ["Signature policy was not evaluated"],
    layers: [],
    config: { User: "1001" },
    ...over,
  });

  it("starts empty, audits a reference, and remembers it", async () => {
    const user = userEvent.setup();
    let sent: unknown = null;
    server.use(
      http.post("/api/registry/inspect", async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json(result());
      }),
    );
    open("/registry");
    expect(await screen.findByText("Check an image before you pull it", undefined, SLOW)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Remote image reference"), "  quay.io/example/app:1.0  {Enter}");
    expect(await screen.findByText("quay.io/example/app:1.0", { selector: "h2" }, SLOW)).toBeInTheDocument();
    expect(sent).toEqual({ reference: "quay.io/example/app:1.0" }); // trimmed
    expect(screen.getByText("Signature policy was not evaluated")).toBeInTheDocument();
    expect(screen.getByText(/Not evaluated before pulling/)).toHaveTextContent("PS-004, PS-010");
    expect(JSON.parse(localStorage.getItem("podshield-registry-recent") ?? "[]")).toEqual(["quay.io/example/app:1.0"]);
  });

  it.each([
    [422, "That reference is not valid", "invalid reference"],
    [503, "Registry auditing is unavailable", "skopeo not installed"],
    [502, "Could not inspect the image", "registry returned 401"],
  ])("explains a %i from the server", async (status, title, detailText) => {
    const user = userEvent.setup();
    server.use(http.post("/api/registry/inspect", () => HttpResponse.json({ detail: detailText }, { status })));
    open("/registry");
    await user.type(await screen.findByLabelText("Remote image reference", undefined, SLOW), "quay.io/example/app{Enter}");
    expect(await screen.findByText(title, undefined, SLOW)).toBeInTheDocument();
    expect(screen.getByText(detailText)).toBeInTheDocument();
  });

  it("ignores an empty submission", async () => {
    const user = userEvent.setup();
    const spy = vi.fn();
    server.use(http.post("/api/registry/inspect", () => (spy(), HttpResponse.json(result()))));
    open("/registry");
    await user.type(await screen.findByLabelText("Remote image reference", undefined, SLOW), "   {Enter}");
    expect(spy).not.toHaveBeenCalled();
  });

  it("renders a shell-metacharacter reference as inert text", async () => {
    const user = userEvent.setup();
    const hostile = "x; rm -rf / $(id) `id`";
    server.use(
      http.post("/api/registry/inspect", () => HttpResponse.json({ detail: "invalid reference" }, { status: 422 })),
    );
    const { container: dom } = open("/registry");
    await user.type(await screen.findByLabelText("Remote image reference", undefined, SLOW), `${hostile}{Enter}`);
    expect(await screen.findByText("That reference is not valid", undefined, SLOW)).toBeInTheDocument();
    expect(dom.querySelector("script")).toBeNull();
  });
});

describe("settings page", () => {
  it("shows version, Podman state and scanner availability", async () => {
    open("/settings");
    expect(await screen.findByText("0.1.0", undefined, SLOW)).toBeInTheDocument();
    expect(screen.getAllByText("Connected").length).toBeGreaterThan(0);
    expect(await screen.findByText(/Unavailable: trivy not found on PATH/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /API documentation/ })).toHaveAttribute("href", "/api/docs");
  });

  it("switches theme with aria-pressed reflecting the choice", async () => {
    const user = userEvent.setup();
    open("/settings");
    const light = await screen.findByRole("button", { name: /^light$/i }, SLOW);
    expect(light).toHaveAttribute("aria-pressed", "false");
    await user.click(light);
    expect(light).toHaveAttribute("aria-pressed", "true");
    expect(localStorage.getItem("podshield-theme")).toBe("light");
  });
});

const vuln = (over: Partial<Vulnerability>): Vulnerability => ({
  cve_id: "CVE-2024-0001",
  package: "openssl",
  severity: "high",
  installed_version: "3.0.1",
  fixed_version: "3.0.7",
  title: "t",
  url: "https://example.invalid/CVE-2024-0001",
  source: "oscap",
  ...over,
});

describe("VulnsTable", () => {
  const vulns = [
    vuln({}),
    vuln({ cve_id: "CVE-2024-0002", package: "zlib", severity: "critical", fixed_version: "", url: "javascript:alert(1)" }),
    vuln({ cve_id: "CVE-2024-0003", package: "glibc", severity: "low", url: "" }),
  ];

  it("sorts worst-first and shows 'no fix yet'", () => {
    render(<VulnsTable vulns={vulns} />);
    const rows = screen.getAllByRole("row").slice(1);
    expect(within(rows[0]).getByText("CVE-2024-0002")).toBeInTheDocument();
    expect(within(rows[0]).getByText("no fix yet")).toBeInTheDocument();
    expect(within(rows[2]).getByText("CVE-2024-0003")).toBeInTheDocument();
  });

  it("only links http(s) URLs, never javascript:", () => {
    render(<VulnsTable vulns={vulns} />);
    expect(screen.getByRole("link", { name: /CVE-2024-0001/ })).toHaveAttribute("href", "https://example.invalid/CVE-2024-0001");
    expect(screen.queryByRole("link", { name: /CVE-2024-0002/ })).not.toBeInTheDocument();
    expect(screen.getByText("CVE-2024-0002")).toBeInTheDocument();
    for (const a of document.querySelectorAll("a")) expect(a.getAttribute("href")).not.toMatch(/^javascript:/i);
  });

  it("filters by text and by severity chip, and says when nothing matches", async () => {
    const user = userEvent.setup();
    render(<VulnsTable vulns={vulns} />);
    await user.type(screen.getByLabelText("Filter vulnerabilities"), "zlib");
    expect(screen.getAllByRole("row")).toHaveLength(2);
    await user.clear(screen.getByLabelText("Filter vulnerabilities"));
    await user.click(screen.getByRole("button", { name: /Low 1/ }));
    expect(screen.getAllByRole("row")).toHaveLength(2);
    await user.click(screen.getByRole("button", { name: /Low 1/ })); // toggles off
    expect(screen.getAllByRole("row")).toHaveLength(4);
    await user.type(screen.getByLabelText("Filter vulnerabilities"), "no-such-package");
    expect(screen.getByText("No CVEs match your filters.")).toBeInTheDocument();
  });

  it("paginates large lists", async () => {
    const many = Array.from({ length: 60 }, (_, i) => vuln({ cve_id: `CVE-2024-${String(i).padStart(4, "0")}` }));
    render(<VulnsTable vulns={many} />);
    expect(screen.getAllByRole("row")).toHaveLength(26); // header + 25
  });

  it("explains why a list is empty", () => {
    const { rerender } = render(<VulnsTable vulns={[]} />);
    expect(screen.getByText("No CVEs recorded")).toBeInTheDocument();
    rerender(<VulnsTable vulns={[]} unavailableNote="CVE scanners were unavailable" />);
    expect(screen.getByText("CVE scanners were unavailable")).toBeInTheDocument();
  });
});

describe("LayersView", () => {
  const layer = (over: Partial<Layer>): Layer => ({ created_by: "RUN dnf install -y x", created: null, size: 1000, empty: false, comment: "", ...over });

  it("shows an empty state without history", () => {
    render(<LayersView layers={[]} />);
    expect(screen.getByText("No layer history")).toBeInTheDocument();
  });

  it("summarises layers and expands a long command", async () => {
    const user = userEvent.setup();
    render(
      <LayersView
        layers={[layer({ size: 5_000_000 }), layer({ empty: true, size: 0, created_by: "ENV A=B" }), layer({ created_by: "" })]}
      />,
    );
    expect(screen.getByText(/3 layers \(2 with content\)/)).toBeInTheDocument();
    expect(screen.getByText("empty")).toBeInTheDocument();
    expect(screen.getByText("(no command recorded)")).toBeInTheDocument();
    const first = screen.getByRole("button", { name: /RUN dnf/ });
    expect(first).toHaveAttribute("aria-expanded", "false");
    await user.click(first);
    expect(first).toHaveAttribute("aria-expanded", "true");
  });

  it("is reachable from image detail", async () => {
    const user = userEvent.setup();
    server.use(
      http.get("/api/images/:id", () =>
        HttpResponse.json(detail({ layers: [layer({}), layer({ created_by: "COPY app /app" })] })),
      ),
    );
    open("/images/abc");
    await user.click(await screen.findByRole("tab", { name: /Layers/ }, SLOW));
    await waitFor(() => expect(screen.getByText(/2 layers/)).toBeInTheDocument());
  });
});
