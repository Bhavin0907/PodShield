import { CheckCircle2, Loader2, X, XCircle } from "lucide-react";
import { useEffect, useRef } from "react";

import { Button } from "@/components/ui/button";
import type { ProgressEvent } from "@/lib/api";
import { type ActiveScan, useScan } from "@/lib/scan-context";
import { cn } from "@/lib/utils";

function describe(ev: ProgressEvent): string {
  switch (ev.stage) {
    case "queued":
      return "Queued";
    case "started":
      return `Started scanning ${ev.message === "all" ? "all images" : ev.message}`;
    case "image_started":
      return `Scanning ${ev.image} (${ev.current}/${ev.total})`;
    case "image_done":
      return `${ev.image}: ${ev.message}`;
    case "image_failed":
      return `${ev.image} failed: ${ev.message}`;
    case "completed":
      return "Scan complete";
    case "failed":
      return `Scan failed${ev.message ? `: ${ev.message}` : ""}`;
  }
}

export function progressPercent(scan: Pick<ActiveScan, "status" | "current" | "total">): number {
  if (scan.status === "completed") return 100;
  if (scan.total <= 0) return 0;
  return Math.min(100, Math.round((scan.current / scan.total) * 100));
}

export function ScanProgressPanel() {
  const { scan, dismiss } = useScan();
  const endRef = useRef<HTMLLIElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "nearest" });
  }, [scan?.log.length]);

  if (!scan) return null;
  const active = scan.status === "queued" || scan.status === "running";
  const pct = progressPercent(scan);

  return (
    <aside
      className="fixed bottom-4 right-4 z-40 w-[min(24rem,calc(100vw-2rem))] animate-fade-in overflow-hidden rounded-2xl border bg-popover shadow-2xl"
      aria-live="polite"
      aria-label="Scan progress"
    >
      <header className="flex items-center gap-3 border-b px-4 py-3">
        {active ? (
          <Loader2 className="size-5 shrink-0 animate-spin text-primary" />
        ) : scan.status === "completed" ? (
          <CheckCircle2 className="size-5 shrink-0 text-primary" />
        ) : (
          <XCircle className="size-5 shrink-0 text-destructive" />
        )}
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold">
            {active ? "Scanning" : scan.status === "completed" ? "Scan complete" : "Scan failed"}: {scan.label}
          </p>
          <p className="truncate text-xs text-muted-foreground">
            Scan #{scan.scanId}
            {scan.status === "queued" && " - waiting for the worker"}
            {scan.status === "running" && scan.total > 0 && ` - ${scan.current} of ${scan.total} images`}
          </p>
        </div>
        {!active && (
          <Button variant="ghost" size="icon" className="size-7" onClick={dismiss} aria-label="Dismiss scan progress">
            <X />
          </Button>
        )}
      </header>

      <div className="px-4 pt-3">
        <div
          className="h-1.5 overflow-hidden rounded-full bg-muted"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
        >
          <div
            className={cn(
              "h-full rounded-full transition-all duration-500",
              scan.status === "failed" ? "bg-destructive" : "bg-primary",
              active && scan.total === 0 && "w-1/3 animate-pulse",
            )}
            style={scan.total === 0 && active ? undefined : { width: `${pct}%` }}
          />
        </div>
        {scan.connectionLost && active && (
          <p className="mt-2 text-xs text-sev-medium">Connection lost, retrying...</p>
        )}
      </div>

      <ul className="max-h-40 space-y-1 overflow-y-auto px-4 py-3 font-mono text-[11px] leading-relaxed text-muted-foreground">
        {scan.log.map((ev, i) => (
          <li key={i} className={cn(ev.stage === "failed" || ev.stage === "image_failed" ? "text-destructive" : undefined)}>
            {describe(ev)}
          </li>
        ))}
        <li ref={endRef} />
      </ul>
    </aside>
  );
}
