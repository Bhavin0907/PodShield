import { describe, expect, it } from "vitest";

import { errorMessage } from "@/lib/api";
import { safeUrl } from "@/lib/constants";
import { type ActiveScan, applyEvent } from "@/lib/scan-context";
import { formatAge, formatBytes, formatDuration, pluralize, timeAgo } from "@/lib/utils";
import { progressPercent } from "@/components/scan-progress";

describe("formatters", () => {
  it("formats bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(250 * 1024 * 1024)).toBe("250 MB");
    expect(formatBytes(3.2 * 1024 ** 3)).toBe("3.2 GB");
  });

  it("formats age", () => {
    expect(formatAge(null)).toBe("unknown");
    expect(formatAge(0)).toBe("today");
    expect(formatAge(12)).toBe("12d");
    expect(formatAge(120)).toBe("4mo");
    expect(formatAge(1000)).toBe("2.7y");
  });

  it("formats durations", () => {
    expect(formatDuration(null)).toBe("-");
    expect(formatDuration(0.2)).toBe("<1s");
    expect(formatDuration(42)).toBe("42s");
    expect(formatDuration(120)).toBe("2m");
    expect(formatDuration(135)).toBe("2m 15s");
  });

  it("formats relative time", () => {
    const now = Date.parse("2026-01-10T12:00:00Z");
    expect(timeAgo(null)).toBe("never");
    expect(timeAgo("2026-01-10T11:59:50Z", now)).toBe("just now");
    expect(timeAgo("2026-01-10T11:30:00Z", now)).toBe("30m ago");
    expect(timeAgo("2026-01-10T07:00:00Z", now)).toBe("5h ago");
    expect(timeAgo("2026-01-05T12:00:00Z", now)).toBe("5d ago");
  });

  it("pluralizes", () => {
    expect(pluralize(1, "image")).toBe("1 image");
    expect(pluralize(2, "image")).toBe("2 images");
  });
});

describe("api helpers", () => {
  it("extracts FastAPI error details", () => {
    expect(errorMessage({ detail: "image not found" }, "x")).toBe("image not found");
    expect(errorMessage({ detail: [{ msg: "bad ref" }, { msg: "too long" }] }, "x")).toBe("bad ref; too long");
    expect(errorMessage({}, "fallback")).toBe("fallback");
    expect(errorMessage(null, "fallback")).toBe("fallback");
  });

  it("only allows http(s) links from scanner data", () => {
    expect(safeUrl("https://access.redhat.com/security/cve/CVE-1")).not.toBeNull();
    expect(safeUrl("http://example.com")).not.toBeNull();
    expect(safeUrl("javascript:alert(1)")).toBeNull();
    expect(safeUrl("data:text/html,<script>")).toBeNull();
    expect(safeUrl("")).toBeNull();
  });
});

describe("scan progress reducer", () => {
  const base: ActiveScan = {
    scanId: 1,
    label: "All images",
    status: "queued",
    current: 0,
    total: 0,
    image: "",
    message: "",
    log: [],
    connectionLost: false,
  };
  const ev = (stage: string, current = 0, total = 0, image = "", message = "") =>
    ({ scan_id: 1, stage, current, total, image, message }) as Parameters<typeof applyEvent>[1];

  it("tracks a full run", () => {
    let s = applyEvent(base, ev("queued"));
    expect(s.status).toBe("queued");
    s = applyEvent(s, ev("started", 0, 0, "", "all"));
    expect(s.status).toBe("running");
    s = applyEvent(s, ev("image_started", 1, 2, "a:1"));
    expect(s.current).toBe(0); // image 1 of 2 is in progress, none finished yet
    expect(progressPercent(s)).toBe(0);
    s = applyEvent(s, ev("image_done", 1, 2, "a:1", "F (40)"));
    expect(s.current).toBe(1);
    expect(progressPercent(s)).toBe(50);
    s = applyEvent(s, ev("image_started", 2, 2, "b:1"));
    expect(progressPercent(s)).toBe(50);
    s = applyEvent(s, ev("image_done", 2, 2, "b:1", "A (100)"));
    s = applyEvent(s, ev("completed", 2, 2));
    expect(s.status).toBe("completed");
    expect(progressPercent(s)).toBe(100);
    expect(s.log).toHaveLength(7);
  });

  it("records failures and keeps the message", () => {
    const s = applyEvent(base, ev("failed", 0, 0, "", "cannot reach Podman"));
    expect(s.status).toBe("failed");
    expect(s.message).toBe("cannot reach Podman");
  });

  it("clears the connection-lost flag when events resume", () => {
    const s = applyEvent({ ...base, connectionLost: true }, ev("started"));
    expect(s.connectionLost).toBe(false);
  });

  it("bounds the log", () => {
    let s = base;
    for (let i = 0; i < 100; i++) s = applyEvent(s, ev("image_done", i, 100, `img${i}`));
    expect(s.log.length).toBeLessThanOrEqual(40);
  });
});
