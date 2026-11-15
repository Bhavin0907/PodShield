import {
  type ColumnDef,
  type SortingState,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { Boxes, FilterX, ScanSearch, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { GradeBadge, SeverityCounters } from "@/components/badges";
import { DataTable } from "@/components/data-table";
import { EmptyState, ErrorState, PageHeader, RowsSkeleton } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { ImageSummary, Severity } from "@/lib/api";
import { GRADES, SEVERITIES, SEVERITY_LABEL } from "@/lib/constants";
import { useImages } from "@/lib/queries";
import { useScan } from "@/lib/scan-context";
import { cn, formatAge, formatBytes, timeAgo } from "@/lib/utils";

const ALL = "all";

const columns: ColumnDef<ImageSummary>[] = [
  {
    id: "name",
    accessorKey: "name",
    header: "Image",
    cell: ({ row }) => (
      <div className="min-w-0 max-w-[17rem]">
        <p className="truncate font-medium">{row.original.name}</p>
        <p className="truncate font-mono text-xs text-muted-foreground">{row.original.short_id}</p>
      </div>
    ),
  },
  {
    id: "grade",
    header: "Grade",
    accessorFn: (r) => r.score ?? -1,
    cell: ({ row }) => <GradeBadge grade={row.original.grade} />,
  },
  {
    id: "score",
    header: "Score",
    accessorFn: (r) => r.score ?? -1,
    cell: ({ row }) => {
      const s = row.original.score;
      return (
        <div className="flex w-28 items-center gap-2">
          <span className="w-8 text-right font-semibold tabular-nums">{s ?? "-"}</span>
          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted" aria-hidden>
            <div
              className={cn(
                "h-full rounded-full",
                (s ?? 0) >= 90 ? "bg-grade-A" : (s ?? 0) >= 80 ? "bg-grade-B" : (s ?? 0) >= 70 ? "bg-grade-C" : (s ?? 0) >= 60 ? "bg-grade-D" : "bg-grade-F",
              )}
              style={{ width: `${s ?? 0}%` }}
            />
          </div>
        </div>
      );
    },
  },
  {
    id: "findings",
    header: "Findings",
    // Worst severity dominates the sort, counts break ties.
    accessorFn: (r) => {
      const c = r.finding_counts;
      return c.critical * 1e6 + c.high * 1e4 + c.medium * 1e2 + c.low;
    },
    cell: ({ row }) => <SeverityCounters counts={row.original.finding_counts} />,
  },
  {
    id: "cves",
    header: "CVEs",
    accessorFn: (r) => r.cve_total,
    cell: ({ row }) => {
      const c = row.original.cve_counts;
      return row.original.cve_total === 0 ? (
        <span className="text-xs text-muted-foreground">0</span>
      ) : (
        <span className="text-xs tabular-nums">
          <span className="font-semibold">{row.original.cve_total}</span>
          {(c.critical > 0 || c.high > 0) && (
            <span className="ml-1.5 text-muted-foreground">
              ({c.critical} crit, {c.high} high)
            </span>
          )}
        </span>
      );
    },
  },
  { id: "size", header: "Size", accessorKey: "size", cell: ({ getValue }) => <span className="tabular-nums">{formatBytes(getValue<number>())}</span> },
  {
    id: "age",
    header: "Age",
    accessorFn: (r) => r.age_days ?? -1,
    cell: ({ row }) => <span className="tabular-nums text-muted-foreground">{formatAge(row.original.age_days)}</span>,
  },
  {
    id: "scanned",
    header: "Last scanned",
    accessorFn: (r) => (r.last_scanned_at ? new Date(r.last_scanned_at).getTime() : 0),
    cell: ({ row }) => <span className="whitespace-nowrap text-muted-foreground">{timeAgo(row.original.last_scanned_at)}</span>,
  },
];

export function filterImages(
  images: ImageSummary[],
  f: { q: string; grade: string; severity: string; registry: string },
): ImageSummary[] {
  const q = f.q.trim().toLowerCase();
  return images.filter((i) => {
    if (q && !(i.name.toLowerCase().includes(q) || i.id.toLowerCase().includes(q) || i.repo_tags.some((t) => t.toLowerCase().includes(q)))) {
      return false;
    }
    if (f.grade !== ALL && i.grade !== f.grade) return false;
    if (f.severity !== ALL && i.finding_counts[f.severity as Severity] === 0) return false;
    if (f.registry !== ALL && i.registry !== f.registry) return false;
    return true;
  });
}

export default function ImagesPage() {
  const { data, isLoading, isError, error, refetch } = useImages();
  const navigate = useNavigate();
  const { start, busy } = useScan();
  const [params, setParams] = useSearchParams();
  const [sorting, setSorting] = useState<SortingState>([{ id: "score", desc: false }]);

  const q = params.get("q") ?? "";
  const grade = params.get("grade") ?? ALL;
  const severity = params.get("severity") ?? ALL;
  const registry = params.get("registry") ?? ALL;

  const setParam = (key: string, value: string) =>
    setParams(
      (cur) => {
        const next = new URLSearchParams(cur);
        if (!value || value === ALL) next.delete(key);
        else next.set(key, value);
        return next;
      },
      { replace: true },
    );

  const registries = useMemo(() => [...new Set((data ?? []).map((i) => i.registry))].sort(), [data]);
  const rows = useMemo(() => filterImages(data ?? [], { q, grade, severity, registry }), [data, q, grade, severity, registry]);
  const filtered = q !== "" || grade !== ALL || severity !== ALL || registry !== ALL;

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <>
      <PageHeader title="Images" description="Every local Podman image with its latest grade. Select a row for the full audit." />

      {isError ? (
        <ErrorState error={error} onRetry={() => void refetch()} title="Could not load images" />
      ) : isLoading ? (
        <RowsSkeleton />
      ) : (data ?? []).length === 0 ? (
        <EmptyState
          icon={Boxes}
          title="No scanned images"
          description="Scan the images on this host to see grades, findings and CVEs here."
          action={
            <Button onClick={() => void start({ all: true }, "All images")} disabled={busy}>
              <ScanSearch /> Scan all images
            </Button>
          }
        />
      ) : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <div className="relative w-full sm:w-72">
              <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={q}
                onChange={(e) => setParam("q", e.target.value)}
                placeholder="Search name, tag or ID"
                aria-label="Search images"
                className="pl-9"
              />
            </div>
            <FilterSelect label="Grade" value={grade} onChange={(v) => setParam("grade", v)} options={GRADES.map((g) => [g, `Grade ${g}`])} />
            <FilterSelect
              label="Severity"
              value={severity}
              onChange={(v) => setParam("severity", v)}
              options={SEVERITIES.map((s) => [s, `Has ${SEVERITY_LABEL[s].toLowerCase()}`])}
            />
            <FilterSelect label="Registry" value={registry} onChange={(v) => setParam("registry", v)} options={registries.map((r) => [r, r])} />
            {filtered && (
              <Button variant="ghost" size="sm" onClick={() => setParams({}, { replace: true })}>
                <FilterX /> Clear
              </Button>
            )}
            <span className="ml-auto text-xs text-muted-foreground" aria-live="polite">
              {rows.length} of {data?.length} images
            </span>
          </div>
          {rows.length === 0 ? (
            <EmptyState
              icon={Search}
              title="No images match"
              description="Try a different search or clear the filters."
              action={
                <Button variant="outline" onClick={() => setParams({}, { replace: true })}>
                  Clear filters
                </Button>
              }
            />
          ) : (
            <DataTable
              table={table}
              onRowClick={(img) => navigate(`/images/${encodeURIComponent(img.id)}`)}
              rowLabel={(img) => `Open ${img.name}`}
            />
          )}
        </>
      )}
    </>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: [string, string][];
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger className="w-auto min-w-[8.5rem]" aria-label={`Filter by ${label.toLowerCase()}`}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{label}: any</SelectItem>
        {options.map(([v, text]) => (
          <SelectItem key={v} value={v}>
            {text}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
