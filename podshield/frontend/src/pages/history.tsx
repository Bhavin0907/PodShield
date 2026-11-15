import { CheckCircle2, ChevronRight, CircleDashed, History as HistoryIcon, Loader2, ScanSearch, XCircle } from "lucide-react";
import { useState } from "react";

import { EmptyState, ErrorState, PageHeader, RowsSkeleton } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { Scan, ScanStatus } from "@/lib/api";
import { SCANNER_LABEL } from "@/lib/constants";
import { useScanDetail, useScans } from "@/lib/queries";
import { useScan } from "@/lib/scan-context";
import { cn, formatDateTime, formatDuration, pluralize, timeAgo } from "@/lib/utils";

const STATUS: Record<ScanStatus, { label: string; cls: string; icon: typeof CheckCircle2 }> = {
  completed: { label: "Completed", cls: "text-primary bg-primary/15", icon: CheckCircle2 },
  failed: { label: "Failed", cls: "text-destructive bg-destructive/15", icon: XCircle },
  running: { label: "Running", cls: "text-sev-low bg-sev-low/15", icon: Loader2 },
  queued: { label: "Queued", cls: "text-muted-foreground bg-muted", icon: CircleDashed },
};

function ScanDetails({ id }: { id: number }) {
  const { data, isLoading } = useScanDetail(id, true);
  if (isLoading || !data) return <Skeleton className="h-16" />;
  return (
    <div className="space-y-3 text-sm">
      {data.error && (
        <p className="break-words rounded-xl border border-destructive/30 bg-destructive/5 px-3 py-2 text-destructive">{data.error}</p>
      )}
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div>
          <dt className="text-xs text-muted-foreground">Started</dt>
          <dd>{formatDateTime(data.started_at)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Finished</dt>
          <dd>{data.finished_at ? formatDateTime(data.finished_at) : "-"}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Duration</dt>
          <dd>{formatDuration(data.duration_seconds)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Images scanned</dt>
          <dd>{data.images_scanned}</dd>
        </div>
      </dl>
      {data.scanners.length > 0 && (
        <div>
          <p className="mb-1.5 text-xs text-muted-foreground">Scanners</p>
          <ul className="flex flex-wrap gap-2">
            {data.scanners.map((s) => (
              <li
                key={s.scanner}
                title={s.detail || undefined}
                className={cn(
                  "rounded-lg border px-2.5 py-1 text-xs",
                  s.status === "ok" ? "border-primary/30 bg-primary/10 text-primary" : "border-sev-medium/30 bg-sev-medium/10 text-sev-medium",
                )}
              >
                {SCANNER_LABEL[s.scanner] ?? s.scanner}: {s.status}
              </li>
            ))}
          </ul>
          {data.scanners.some((s) => s.status !== "ok" && s.detail) && (
            <ul className="mt-2 space-y-0.5 text-xs text-muted-foreground">
              {data.scanners
                .filter((s) => s.status !== "ok" && s.detail)
                .map((s) => (
                  <li key={s.scanner}>
                    {SCANNER_LABEL[s.scanner] ?? s.scanner}: {s.detail}
                  </li>
                ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

function TimelineItem({ scan, last }: { scan: Scan; last: boolean }) {
  const [open, setOpen] = useState(false);
  const st = STATUS[scan.status];
  const Icon = st.icon;
  return (
    <li className="relative flex gap-4">
      {!last && <span className="absolute left-[1.05rem] top-10 -bottom-3 w-px bg-border" aria-hidden />}
      <div className={cn("z-10 mt-1 flex size-9 shrink-0 items-center justify-center rounded-full", st.cls)}>
        <Icon className={cn("size-4", scan.status === "running" && "animate-spin")} />
      </div>
      <Card className="mb-3 min-w-0 flex-1">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="flex w-full items-center gap-3 rounded-2xl p-4 text-left transition-colors hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">
              Scan #{scan.id}
              <span className="ml-2 font-normal text-muted-foreground">{scan.target === "all" ? "All images" : scan.target}</span>
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground" title={formatDateTime(scan.started_at)}>
              {timeAgo(scan.started_at)} - {formatDuration(scan.duration_seconds)} - {pluralize(scan.images_scanned, "image")}
            </p>
          </div>
          <span className={cn("rounded-md px-2 py-0.5 text-xs font-semibold", st.cls)}>{st.label}</span>
          <ChevronRight className={cn("size-4 text-muted-foreground transition-transform", open && "rotate-90")} />
        </button>
        {open && (
          <div className="animate-fade-in border-t p-4">
            <ScanDetails id={scan.id} />
          </div>
        )}
      </Card>
    </li>
  );
}

export default function HistoryPage() {
  const { data, isLoading, isError, error, refetch } = useScans();
  const { start, busy } = useScan();

  return (
    <>
      <PageHeader title="Scan History" description="Every scan, whether started here, from the CLI, the timer or the events watcher." />
      {isError ? (
        <ErrorState error={error} onRetry={() => void refetch()} title="Could not load scan history" />
      ) : isLoading || !data ? (
        <RowsSkeleton />
      ) : data.length === 0 ? (
        <EmptyState
          icon={HistoryIcon}
          title="No scans yet"
          description="Scans appear here with their status, duration and which scanners were available."
          action={
            <Button onClick={() => void start({ all: true }, "All images")} disabled={busy}>
              <ScanSearch /> Scan all images
            </Button>
          }
        />
      ) : (
        <ol>
          {data.map((scan, i) => (
            <TimelineItem key={scan.id} scan={scan} last={i === data.length - 1} />
          ))}
        </ol>
      )}
    </>
  );
}
