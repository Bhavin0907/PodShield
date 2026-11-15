import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";

import { detail, health, overview, rules, scan, summary } from "@/test/fixtures";

/** Happy-path defaults. Individual tests override with `server.use(...)`. */
export const handlers = [
  http.get("/api/overview", () => HttpResponse.json(overview())),
  http.get("/api/images", () => HttpResponse.json([summary()])),
  http.get("/api/images/:id", () => HttpResponse.json(detail())),
  http.get("/api/scans", () => HttpResponse.json([scan()])),
  http.get("/api/scans/:id", () => HttpResponse.json({ ...scan(), scanners: [] })),
  http.post("/api/scans", () => HttpResponse.json({ scan_id: 8, status: "queued" }, { status: 202 })),
  http.get("/api/containers", () => HttpResponse.json([])),
  http.get("/api/rules", () => HttpResponse.json(rules())),
  http.get("/api/health", () => HttpResponse.json(health())),
];

export const server = setupServer(...handlers);
export { HttpResponse, http };
