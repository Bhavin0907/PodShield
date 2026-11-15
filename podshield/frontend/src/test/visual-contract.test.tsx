/** The colour language of the UI: grades, severities and the score ring. */
import fs from "node:fs";
import path from "node:path";

import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GradeBadge, SeverityBadge, SeverityCounters } from "@/components/badges";
import { ScoreRing } from "@/components/score-ring";
import type { Grade, Severity } from "@/lib/api";
import { GRADES, GRADE_CLASS, GRADE_COLOR, SEVERITIES, SEVERITY_CLASS, SEVERITY_COLOR, SEVERITY_DOT } from "@/lib/constants";
import { counts } from "@/test/fixtures";

const tailwind = fs.readFileSync(path.resolve(__dirname, "../../tailwind.config.js"), "utf8");

function paletteHex(group: "sev" | "grade", key: string): string | undefined {
  const block = new RegExp(`${group}:\\s*\\{([^}]*)\\}`).exec(tailwind)?.[1] ?? "";
  return new RegExp(`${key}:\\s*"(#[0-9a-fA-F]{6})"`).exec(block)?.[1];
}

describe("grade badge colours", () => {
  it.each(GRADES)("grade %s has its own colour classes", (grade) => {
    render(<GradeBadge grade={grade} />);
    const el = screen.getByLabelText(`Grade ${grade}`);
    expect(el).toHaveTextContent(grade);
    expect(el.className).toContain(`text-grade-${grade}`);
    expect(el.className).toContain(`bg-grade-${grade}/15`);
    expect(el.className).toContain(`border-grade-${grade}/30`);
  });

  it("uses a different colour for every grade", () => {
    expect(new Set(GRADES.map((g) => GRADE_COLOR[g])).size).toBe(GRADES.length);
  });

  it("renders a neutral placeholder for an unscored image", () => {
    const { container } = render(<GradeBadge grade={null} />);
    expect(container.textContent).toBe("?");
    expect(container.firstElementChild?.className).not.toMatch(/grade-[A-F]/);
  });

  it.each(["sm", "md", "lg"] as const)("supports the %s size", (size) => {
    render(<GradeBadge grade="B" size={size} />);
    expect(screen.getByLabelText("Grade B")).toBeInTheDocument();
  });
});

describe("severity colours", () => {
  it.each(SEVERITIES)("%s badge carries its severity classes and label", (sev) => {
    const { container } = render(<SeverityBadge severity={sev} />);
    expect(container.textContent?.toLowerCase()).toBe(sev);
    expect(container.firstElementChild?.className).toContain(`text-sev-${sev}`);
    expect(SEVERITY_CLASS[sev]).toContain(`bg-sev-${sev}/15`);
    expect(SEVERITY_DOT[sev]).toBe(`bg-sev-${sev}`);
  });

  it("uses a distinct colour per severity", () => {
    expect(new Set(SEVERITIES.map((s) => SEVERITY_COLOR[s])).size).toBe(SEVERITIES.length);
  });

  it("dims zero counts so non-zero ones stand out", () => {
    render(<SeverityCounters counts={counts({ critical: 3 })} />);
    const critical = screen.getByTitle("3 critical");
    const high = screen.getByTitle("0 high");
    expect(critical.className).not.toContain("opacity-35");
    expect(high.className).toContain("opacity-35");
  });

  it("can hide the info column", () => {
    render(<SeverityCounters counts={counts({ info: 9 })} hideInfo />);
    expect(screen.queryByTitle("9 info")).not.toBeInTheDocument();
  });
});

describe("palette stays in sync with Tailwind", () => {
  // The charts use hexes from constants.ts, the badges use Tailwind classes. If they drift apart the
  // same severity would be two different colours on one page.
  it.each(SEVERITIES)("severity %s: chart hex equals tailwind hex", (sev: Severity) => {
    expect(paletteHex("sev", sev)?.toLowerCase()).toBe(SEVERITY_COLOR[sev].toLowerCase());
  });
  it.each(GRADES)("grade %s: chart hex equals tailwind hex", (grade: Grade) => {
    expect(paletteHex("grade", grade)?.toLowerCase()).toBe(GRADE_COLOR[grade].toLowerCase());
  });
  it("every grade class string names its own grade", () => {
    for (const g of GRADES) expect(GRADE_CLASS[g].match(/grade-([A-F])/g)?.every((m) => m === `grade-${g}`)).toBe(true);
  });
});

describe("score ring", () => {
  const ring = () => {
    const circles = document.querySelectorAll("circle");
    const arc = circles[1] as SVGCircleElement;
    const circumference = Number(arc.getAttribute("stroke-dasharray"));
    const offset = Number(arc.getAttribute("stroke-dashoffset"));
    return { arc, fraction: 1 - offset / circumference };
  };

  it.each([
    [0, 0],
    [25, 0.25],
    [87, 0.87],
    [100, 1],
  ])("score %i fills %f of the ring", async (score, fraction) => {
    render(<ScoreRing score={score} grade="B" />);
    await waitFor(() => expect(ring().fraction).toBeCloseTo(fraction, 5));
  });

  it("clamps out-of-range scores", async () => {
    const high = render(<ScoreRing score={250} grade="A" />);
    await waitFor(() => expect(ring().fraction).toBeCloseTo(1, 5));
    high.unmount();
    render(<ScoreRing score={-30} grade="F" />);
    expect(ring().fraction).toBeCloseTo(0, 5);
  });

  it.each(GRADES)("strokes grade %s in the grade colour", (grade) => {
    render(<ScoreRing score={50} grade={grade} />);
    expect(ring().arc.getAttribute("stroke")).toBe(GRADE_COLOR[grade]);
  });

  it("is grey when unscored and shows a dash", () => {
    render(<ScoreRing score={null} grade={null} />);
    expect(ring().arc.getAttribute("stroke")).toBe("#71717a");
    expect(screen.getByRole("img", { name: "Not scored" })).toHaveTextContent("-");
    expect(ring().fraction).toBeCloseTo(0, 5);
  });

  it("shows the grade label when asked, and hides '/ 100' on small rings", () => {
    const big = render(<ScoreRing score={90} grade="A" showGrade />);
    expect(screen.getByText("Grade A")).toBeInTheDocument();
    big.unmount();
    render(<ScoreRing score={90} grade="A" size={64} />);
    expect(screen.queryByText("/ 100")).not.toBeInTheDocument();
  });
});
