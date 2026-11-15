/** Typed client for the PodShield API. Types mirror backend/podshield/api_models.py. */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Grade = "A" | "B" | "C" | "D" | "F";
export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type ScannerState = "ok" | "unavailable" | "unsupported" | "partial" | "failed";

export type SeverityCounts = Record<Severity, number>;

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  description: string;
  evidence: string[];
  remediation: string;
}

export interface Vulnerability {
  cve_id: string;
  package: string;
  severity: Severity;
  installed_version: string;
  fixed_version: string;
  title: string;
  url: string;
  source: string;
}

export interface ImageSummary {
  id: string;
  short_id: string;
  name: string;
  repo_tags: string[];
  registry: string;
  size: number;
  created: string | null;
  age_days: number | null;
  score: number | null;
  grade: Grade | null;
  last_scanned_at: string | null;
  finding_counts: SeverityCounts;
  cve_counts: SeverityCounts;
  cve_total: number;
}

export interface Layer {
  created_by: string;
  created: string | null;
  size: number;
  empty: boolean;
  comment: string;
}

export interface HistoryPoint {
  scan_id: number;
  scanned_at: string;
  score: number;
  grade: Grade;
  finding_count: number;
}

export interface ScannerRun {
  scanner: string;
  status: ScannerState;
  detail: string;
}

export interface ImageDetail extends ImageSummary {
  base_image: string | null;
  last_scan_id: number | null;
  findings: Finding[];
  vulnerabilities: Vulnerability[];
  layers: Layer[];
  config: Record<string, unknown> | null;
  history: HistoryPoint[];
  scanners: ScannerRun[];
}

export interface TrendPoint {
  scan_id: number;
  at: string;
  score: number;
}

export interface Overview {
  images_audited: number;
  fleet_score: number | null;
  fleet_grade: Grade | null;
  grade_distribution: Record<Grade, number>;
  severity_totals: SeverityCounts;
  cve_totals: SeverityCounts;
  critical_findings: number;
  total_cves: number;
  trend: TrendPoint[];
  riskiest: ImageSummary[];
  last_scan_at: string | null;
}

export interface Scan {
  id: number;
  target: string;
  status: ScanStatus;
  started_at: string;
  finished_at: string | null;
  duration_seconds: number | null;
  images_scanned: number;
  error: string | null;
}

export interface ScanDetail extends Scan {
  scanners: ScannerRun[];
}

export interface ScanRequest {
  image?: string;
  all?: boolean;
  skip_filesystem?: boolean;
  skip_cve?: boolean;
}

export interface ProgressEvent {
  scan_id: number;
  stage: "queued" | "started" | "image_started" | "image_done" | "image_failed" | "completed" | "failed";
  current: number;
  total: number;
  image: string;
  message: string;
}

export interface Rule {
  id: string;
  title: string;
  description: string;
  kind: "image" | "runtime";
  default_severity: Severity;
  severity: Severity;
  enabled: boolean;
}

export interface RulePatch {
  enabled?: boolean | null;
  severity?: Severity | null;
}

export interface Container {
  id: string;
  short_id: string;
  name: string;
  image: string;
  status: string;
  score: number;
  grade: Grade;
  findings: Finding[];
}

export interface RegistryResult {
  reference: string;
  id: string;
  score: number;
  grade: Grade;
  size: number;
  created: string | null;
  findings: Finding[];
  skipped_rules: string[];
  notes: string[];
  layers: Layer[];
  config: Record<string, unknown>;
}

export interface ScannerStatus {
  available: boolean;
  enabled: boolean;
  detail: string;
}

export interface Health {
  status: string;
  version: string;
  podman: boolean;
  scanners: Record<string, ScannerStatus>;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** FastAPI returns `detail` as a string, or as a list of validation errors (422). */
export function errorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const parts = detail
        .map((d) => (d && typeof d === "object" && "msg" in d ? String((d as { msg: unknown }).msg) : ""))
        .filter(Boolean);
      if (parts.length) return parts.join("; ");
    }
  }
  return fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}) },
    });
  } catch {
    throw new ApiError(0, "Cannot reach the PodShield server. Is the API service running?");
  }
  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, errorMessage(body, `${res.status} ${res.statusText}`));
  }
  return (await res.json()) as T;
}

const json = (method: string, body: unknown): RequestInit => ({ method, body: JSON.stringify(body) });

export const api = {
  overview: () => request<Overview>("/api/overview"),
  images: () => request<ImageSummary[]>("/api/images"),
  image: (id: string) => request<ImageDetail>(`/api/images/${encodeURIComponent(id)}`),
  scans: (limit = 100) => request<Scan[]>(`/api/scans?limit=${limit}`),
  scan: (id: number) => request<ScanDetail>(`/api/scans/${id}`),
  createScan: (body: ScanRequest) => request<{ scan_id: number; status: string }>("/api/scans", json("POST", body)),
  containers: () => request<Container[]>("/api/containers"),
  registryInspect: (reference: string) =>
    request<RegistryResult>("/api/registry/inspect", json("POST", { reference })),
  rules: () => request<Rule[]>("/api/rules"),
  patchRule: (id: string, patch: RulePatch) => request<Rule>(`/api/rules/${encodeURIComponent(id)}`, json("PATCH", patch)),
  health: () => request<Health>("/api/health"),
  reportUrl: (imageId: string) => `/api/reports/${encodeURIComponent(imageId)}.html`,
  streamUrl: (scanId: number) => `/api/scans/${scanId}/stream`,
};

export const TERMINAL_STAGES: ReadonlySet<ProgressEvent["stage"]> = new Set(["completed", "failed"]);
