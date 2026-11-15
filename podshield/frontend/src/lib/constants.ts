import type { Grade, Severity } from "@/lib/api";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const GRADES: Grade[] = ["A", "B", "C", "D", "F"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Same hexes as tailwind.config.js (charts cannot use Tailwind classes). */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#38bdf8",
  info: "#a1a1aa",
};

export const GRADE_COLOR: Record<Grade, string> = {
  A: "#10b981",
  B: "#84cc16",
  C: "#f59e0b",
  D: "#f97316",
  F: "#ef4444",
};

/** Full class names so Tailwind's scanner sees them. */
export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/15 text-sev-high border-sev-high/30",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  low: "bg-sev-low/15 text-sev-low border-sev-low/30",
  info: "bg-sev-info/15 text-sev-info border-sev-info/30",
};

export const SEVERITY_DOT: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export const GRADE_CLASS: Record<Grade, string> = {
  A: "bg-grade-A/15 text-grade-A border-grade-A/30",
  B: "bg-grade-B/15 text-grade-B border-grade-B/30",
  C: "bg-grade-C/15 text-grade-C border-grade-C/30",
  D: "bg-grade-D/15 text-grade-D border-grade-D/30",
  F: "bg-grade-F/15 text-grade-F border-grade-F/30",
};

export const SCANNER_LABEL: Record<string, string> = {
  filesystem: "Filesystem mount",
  oscap: "OpenSCAP (OVAL)",
  trivy: "Trivy",
  skopeo: "Skopeo (registry)",
  trust: "Signature policy",
};

/** Only http(s) links from scanner data are rendered as anchors (blocks javascript: URLs). */
export function safeUrl(url: string): string | null {
  return /^https?:\/\//i.test(url) ? url : null;
}
