import { ArrowLeft, Download, FileQuestion, Layers, Loader2, RefreshCw, Tag } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { Area, AreaChart, ResponsiveContainer, Tooltip as ChartTooltip, YAxis } from "recharts";

import { GradeBadge, SeverityCounters } from "@/components/badges";
import { CopyButton } from "@/components/code-block";
import { ReportTabs } from "@/components/report-tabs";
import { ScoreRing } from "@/components/score-ring";
import { EmptyState, ErrorState, Notice } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError, type ImageDetail, api } from "@/lib/api";
import { SCANNER_LABEL } from "@/lib/constants";
import { useImage } from "@/lib/queries";
import { useScan } from "@/lib/scan-context";
import { formatAge, formatBytes, formatDateTime, timeAgo } from "@/lib/utils";

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 truncate text-sm font-medium">{children}</dd>
    </div>
  );
}

function HistorySpark({ history }: { history: ImageDetail["history"] }) {
  if (history.length < 2) return null;
  const rows = history.map((h) => ({ score: h.score, at: new Date(h.scanned_at).toLocaleString() }));
  return (
    <div className="hidden w-48 shrink-0 xl:block">
      <p className="mb-1 text-xs text-muted-foreground">Score history ({history.length} scans)</p>
      <ResponsiveContainer width="100%" height={56}>
        <AreaChart data={rows} margin={{ top: 4, right: 2, left: 2, bottom: 0 }}>
          <defs>
            <linearGradient id="histFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10b981" stopOpacity={0.3} />
              <stop offset="100%" stopColor="#10b981" stopOpacity={0} />
            </linearGradient>
          </defs>
          <YAxis domain={[0, 100]} hide />
          <ChartTooltip
            contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 10, fontSize: 11 }}
            formatter={(v: number) => [v, "Score"]}
            labelFormatter={() => ""}
          />
          <Area type="monotone" dataKey="score" stroke="#10b981" strokeWidth={2} fill="url(#histFill)" dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function scannerNotices(scanners: ImageDetail["scanners"]) {
  return scanners.filter((s) => s.status !== "ok");
}

function Header({ image }: { image: ImageDetail }) {
  const { start, busy } = useScan();
  return (
    <Card className="mb-6 p-6">
      <div className="flex flex-wrap items-center gap-6">
        <ScoreRing score={image.score} grade={image.grade} size={132} />
        <div className="min-w-0 flex-1 basis-72">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="break-all text-2xl font-semibold tracking-tight">{image.name}</h1>
            <GradeBadge grade={image.grade} size="lg" />
          </div>
          <div className="mt-1 flex items-center gap-1 font-mono text-xs text-muted-foreground">
            {image.short_id}
            <CopyButton text={image.id} label="ID" className="h-6" />
          </div>
          {image.repo_tags.length > 1 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {image.repo_tags.map((t) => (
                <span key={t} className="inline-flex items-center gap-1 rounded-md bg-muted px-2 py-0.5 font-mono text-[11px]">
                  <Tag className="size-3" />
                  {t}
                </span>
              ))}
            </div>
          )}
          <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
            <Meta label="Size">{formatBytes(image.size)}</Meta>
            <Meta label="Age">
              {formatAge(image.age_days)}
              {image.age_days !== null && image.age_days >= 1 && " old"}
            </Meta>
            <Meta label="Base image">
              <span title={image.base_image ?? undefined}>{image.base_image ?? "unknown"}</span>
            </Meta>
            <Meta label="Last scanned">
              <span title={formatDateTime(image.last_scanned_at)}>{timeAgo(image.last_scanned_at)}</span>
            </Meta>
          </dl>
          <SeverityCounters counts={image.finding_counts} className="mt-4" />
        </div>
        <HistorySpark history={image.history} />
        <div className="flex w-full flex-wrap gap-2 sm:w-auto sm:flex-col">
          <Button onClick={() => void start({ image: image.id }, image.name)} disabled={busy}>
            {busy ? <Loader2 className="animate-spin" /> : <RefreshCw />} Rescan
          </Button>
          <Button asChild variant="outline">
            <a href={api.reportUrl(image.id)} download>
              <Download /> Download report
            </a>
          </Button>
        </div>
      </div>
    </Card>
  );
}

export default function ImageDetailPage() {
  const { id = "" } = useParams();
  const { data, isLoading, isError, error, refetch } = useImage(id);

  const back = (
    <Button asChild variant="ghost" size="sm" className="mb-4 -ml-2">
      <Link to="/images">
        <ArrowLeft /> All images
      </Link>
    </Button>
  );

  if (isError) {
    if (error instanceof ApiError && (error.status === 404 || error.status === 409)) {
      return (
        <>
          {back}
          <EmptyState
            icon={FileQuestion}
            title={error.status === 404 ? "Image not found" : "Ambiguous image ID"}
            description={
              error.status === 404
                ? "This image has not been scanned, or it was removed. Scan the host again to refresh the inventory."
                : error.message
            }
            action={
              <Button asChild variant="outline">
                <Link to="/images">Back to images</Link>
              </Button>
            }
          />
        </>
      );
    }
    return (
      <>
        {back}
        <ErrorState error={error} onRetry={() => void refetch()} title="Could not load this image" />
      </>
    );
  }

  if (isLoading || !data) {
    return (
      <>
        {back}
        <Card className="mb-6 flex gap-6 p-6">
          <Skeleton className="size-32 rounded-full" />
          <div className="flex-1 space-y-3">
            <Skeleton className="h-7 w-1/2" />
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-12 w-full" />
          </div>
        </Card>
        <Skeleton className="h-64 rounded-2xl" />
      </>
    );
  }

  const degraded = scannerNotices(data.scanners);
  const cveScanners = data.scanners.filter((s) => s.scanner === "oscap" || s.scanner === "trivy");
  const cveBlind = cveScanners.length > 0 && cveScanners.every((s) => s.status !== "ok");

  return (
    <>
      {back}
      <Header image={data} />
      {degraded.length > 0 && (
        <div className="mb-6">
          <Notice tone="warn" title="Some checks could not run during the last scan">
            <ul className="mt-1 space-y-0.5">
              {degraded.map((s) => (
                <li key={s.scanner}>
                  <span className="font-medium text-foreground">{SCANNER_LABEL[s.scanner] ?? s.scanner}</span> ({s.status}
                  {s.detail ? `: ${s.detail}` : ""})
                </li>
              ))}
            </ul>
            <p className="mt-1.5">Findings that depend on these scanners are missing, so the grade may be optimistic.</p>
          </Notice>
        </div>
      )}
      <ReportTabs
        findings={data.findings}
        vulnerabilities={data.vulnerabilities}
        layers={data.layers}
        config={data.config}
        cveNote={
          cveBlind
            ? "CVE scanners were unavailable during the last scan, so no vulnerability data was collected. See the notice above."
            : undefined
        }
      />
      {data.layers.length === 0 && (
        <p className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground">
          <Layers className="size-3.5" /> Layer history is unavailable for this image.
        </p>
      )}
    </>
  );
}
