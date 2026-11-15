import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { GradeBadge, SeverityBadge } from "@/components/badges";
import { FindingsList } from "@/components/findings-list";
import { highlightJson } from "@/components/json-view";
import { ScoreRing } from "@/components/score-ring";
import type { Finding } from "@/lib/api";

const finding = (over: Partial<Finding>): Finding => ({
  rule_id: "PS-001",
  title: "Container runs as root",
  severity: "high",
  description: "No USER instruction.",
  evidence: ["USER not set"],
  remediation: "USER 1001",
  ...over,
});

describe("ScoreRing", () => {
  it("describes the score for screen readers", () => {
    render(<ScoreRing score={87} grade="B" />);
    expect(screen.getByRole("img", { name: "Score 87 out of 100, grade B" })).toBeInTheDocument();
  });

  it("handles unscored images", () => {
    render(<ScoreRing score={null} grade={null} />);
    expect(screen.getByRole("img", { name: "Not scored" })).toBeInTheDocument();
  });
});

describe("badges", () => {
  it("renders severity and grade", () => {
    render(
      <>
        <SeverityBadge severity="critical" />
        <GradeBadge grade="F" />
      </>,
    );
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByLabelText("Grade F")).toBeInTheDocument();
  });
});

describe("FindingsList", () => {
  it("groups by severity, worst first", () => {
    render(
      <FindingsList
        findings={[
          finding({ rule_id: "PS-011", severity: "low", title: "No HEALTHCHECK" }),
          finding({ rule_id: "PS-003", severity: "critical", title: "Secrets in ENV" }),
        ]}
      />,
    );
    const headings = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
    expect(headings[0]).toMatch(/Critical/);
    expect(headings[1]).toMatch(/Low/);
  });

  it("expands to show evidence and a copyable remediation", async () => {
    const user = userEvent.setup();
    render(<FindingsList findings={[finding({})]} />);
    expect(screen.queryByText("USER 1001")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Container runs as root/ }));
    expect(screen.getByText("USER not set")).toBeInTheDocument();
    expect(screen.getByText("USER 1001")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /copy/i })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Container runs as root/ }));
    expect(screen.queryByText("USER 1001")).not.toBeInTheDocument();
  });

  it("expands and collapses everything", async () => {
    const user = userEvent.setup();
    render(<FindingsList findings={[finding({}), finding({ rule_id: "PS-002", title: "Uses :latest", severity: "medium" })]} />);
    await user.click(screen.getByRole("button", { name: "Expand all" }));
    expect(screen.getAllByText("Evidence")).toHaveLength(2);
    await user.click(screen.getByRole("button", { name: "Collapse all" }));
    expect(screen.queryByText("Evidence")).not.toBeInTheDocument();
  });

  it("shows an empty state", () => {
    render(<FindingsList findings={[]} />);
    expect(screen.getByText("No findings")).toBeInTheDocument();
  });

  it("renders hostile text as text, never as markup", async () => {
    const user = userEvent.setup();
    const xss = "<img src=x onerror=alert(1)>";
    const { container } = render(<FindingsList findings={[finding({ title: xss, evidence: [xss], remediation: xss })]} />);
    await user.click(screen.getByRole("button", { name: /onerror/ }));
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getAllByText(xss).length).toBeGreaterThan(0);
  });
});

describe("highlightJson", () => {
  it("preserves the text exactly", () => {
    const text = JSON.stringify({ user: "root", n: 3, ok: true, none: null, env: ["A=b"] }, null, 2);
    const { container } = render(<pre>{highlightJson(text)}</pre>);
    expect(container.textContent).toBe(text);
  });

  it("never injects html", () => {
    const text = JSON.stringify({ k: "<b>bold</b>" }, null, 2);
    const { container } = render(<pre>{highlightJson(text)}</pre>);
    expect(container.querySelector("b")).toBeNull();
  });
});
