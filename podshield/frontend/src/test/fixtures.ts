/** Typed API fixtures shared by the MSW-backed tests. All secrets here are documented fakes. */
import type {
  Finding,
  Health,
  ImageDetail,
  ImageSummary,
  Overview,
  Rule,
  Scan,
  SeverityCounts,
} from "@/lib/api";

export const counts = (o: Partial<SeverityCounts> = {}): SeverityCounts => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
  ...o,
});

export const finding = (over: Partial<Finding> = {}): Finding => ({
  rule_id: "PS-001",
  title: "Container runs as root",
  severity: "high",
  description: "No USER instruction.",
  evidence: ["USER not set"],
  remediation: "USER 1001",
  ...over,
});

export const summary = (over: Partial<ImageSummary> = {}): ImageSummary => ({
  id: "a".repeat(64),
  short_id: "aaaaaaaaaaaa",
  name: "localhost/pstest-bad:latest",
  repo_tags: ["localhost/pstest-bad:latest"],
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

/** Masked exactly as the backend does it: first four characters, then ****. */
export const MASKED_AWS = "AKIA****";
export const MASKED_PASSWORD = "hunt****";
export const RAW_AWS = "AKIAIOSFODNN7EXAMPLE";
export const RAW_PASSWORD = "hunter2-super-secret";

export const detail = (over: Partial<ImageDetail> = {}): ImageDetail => ({
  ...summary(),
  base_image: "registry.access.redhat.com/ubi9/ubi-minimal:9.4",
  last_scan_id: 7,
  findings: [
    finding({ rule_id: "PS-011", severity: "low", title: "No HEALTHCHECK" }),
    finding({
      rule_id: "PS-003",
      severity: "critical",
      title: "Secrets in ENV",
      evidence: [`AWS_ACCESS_KEY_ID=${MASKED_AWS}`, `DB_PASSWORD=${MASKED_PASSWORD}`],
    }),
    finding({ rule_id: "PS-001", severity: "high", title: "Container runs as root" }),
    finding({ rule_id: "PS-005", severity: "high", title: "Image is stale" }),
    finding({ rule_id: "PS-012", severity: "medium", title: "Missing labels" }),
  ],
  vulnerabilities: [],
  layers: [],
  config: { User: "", Env: [`AWS_ACCESS_KEY_ID=${MASKED_AWS}`, `DB_PASSWORD=${MASKED_PASSWORD}`, "LANG=C.UTF-8"] },
  history: [],
  scanners: [
    { scanner: "filesystem", status: "ok", detail: "" },
    { scanner: "oscap", status: "ok", detail: "" },
    { scanner: "trivy", status: "ok", detail: "" },
  ],
  ...over,
});

export const overview = (over: Partial<Overview> = {}): Overview => ({
  images_audited: 2,
  fleet_score: 70,
  fleet_grade: "C",
  grade_distribution: { A: 1, B: 0, C: 0, D: 0, F: 1 },
  severity_totals: counts({ critical: 1, high: 2 }),
  cve_totals: counts({ high: 3 }),
  critical_findings: 1,
  total_cves: 3,
  trend: [
    { scan_id: 1, at: "2026-11-14T10:00:00Z", score: 60 },
    { scan_id: 2, at: "2026-11-15T10:00:00Z", score: 70 },
  ],
  riskiest: [summary()],
  last_scan_at: "2026-11-15T10:00:00Z",
  ...over,
});

export const health = (over: Partial<Health> = {}): Health => ({
  status: "ok",
  version: "0.1.0",
  podman: true,
  scanners: {
    filesystem: { available: true, enabled: true, detail: "" },
    oscap: { available: true, enabled: true, detail: "" },
    trivy: { available: false, enabled: true, detail: "trivy not found on PATH" },
  },
  ...over,
});

export const rules = (): Rule[] => [
  {
    id: "PS-001",
    title: "Container runs as root",
    description: "d",
    kind: "image",
    default_severity: "high",
    severity: "high",
    enabled: true,
  },
];

export const scan = (over: Partial<Scan> = {}): Scan => ({
  id: 7,
  target: "all",
  status: "completed",
  started_at: "2026-11-15T10:00:00Z",
  finished_at: "2026-11-15T10:00:30Z",
  duration_seconds: 30,
  images_scanned: 2,
  error: null,
  ...over,
});
