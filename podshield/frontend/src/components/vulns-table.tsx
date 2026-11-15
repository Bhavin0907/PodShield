import {
  type ColumnDef,
  type SortingState,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { Bug, ExternalLink, Search } from "lucide-react";
import { useMemo, useState } from "react";

import { SeverityBadge } from "@/components/badges";
import { DataTable, Pagination } from "@/components/data-table";
import { EmptyState } from "@/components/states";
import { Input } from "@/components/ui/input";
import type { Severity, Vulnerability } from "@/lib/api";
import { SEVERITIES, SEVERITY_CLASS, SEVERITY_LABEL, SEVERITY_RANK, safeUrl } from "@/lib/constants";
import { cn } from "@/lib/utils";

const columns: ColumnDef<Vulnerability>[] = [
  {
    accessorKey: "cve_id",
    header: "CVE",
    cell: ({ row }) => {
      const url = safeUrl(row.original.url);
      const id = row.original.cve_id;
      return url ? (
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline"
          title={row.original.title || id}
        >
          {id}
          <ExternalLink className="size-3" />
        </a>
      ) : (
        <span className="font-mono text-xs" title={row.original.title || id}>
          {id}
        </span>
      );
    },
  },
  {
    accessorKey: "severity",
    header: "Severity",
    sortingFn: (a, b) => SEVERITY_RANK[a.original.severity] - SEVERITY_RANK[b.original.severity],
    cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
  },
  { accessorKey: "package", header: "Package", cell: ({ getValue }) => <span className="font-mono text-xs">{String(getValue() || "-")}</span> },
  {
    accessorKey: "installed_version",
    header: "Installed",
    cell: ({ getValue }) => <span className="font-mono text-xs text-muted-foreground">{String(getValue() || "-")}</span>,
  },
  {
    accessorKey: "fixed_version",
    header: "Fixed in",
    cell: ({ getValue }) => {
      const v = String(getValue() || "");
      return v ? (
        <span className="font-mono text-xs text-primary">{v}</span>
      ) : (
        <span className="text-xs text-muted-foreground">no fix yet</span>
      );
    },
  },
  { accessorKey: "source", header: "Source", cell: ({ getValue }) => <span className="text-xs text-muted-foreground">{String(getValue())}</span> },
];

export function VulnsTable({ vulns, unavailableNote }: { vulns: Vulnerability[]; unavailableNote?: string }) {
  const [sorting, setSorting] = useState<SortingState>([{ id: "severity", desc: true }]);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "all">("all");

  const counts = useMemo(() => {
    const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const v of vulns) c[v.severity] += 1;
    return c;
  }, [vulns]);

  const data = useMemo(() => {
    const q = query.trim().toLowerCase();
    return vulns.filter(
      (v) =>
        (severity === "all" || v.severity === severity) &&
        (!q || v.cve_id.toLowerCase().includes(q) || v.package.toLowerCase().includes(q)),
    );
  }, [vulns, query, severity]);

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 25 } },
  });

  if (vulns.length === 0) {
    return (
      <EmptyState
        icon={Bug}
        title="No CVEs recorded"
        description={
          unavailableNote ??
          "No known vulnerabilities were reported by the CVE scanners for this image."
        }
      />
    );
  }

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by CVE or package"
            aria-label="Filter vulnerabilities"
            className="pl-9"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setSeverity("all")}
            className={cn(
              "rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors",
              severity === "all" ? "bg-foreground text-background" : "text-muted-foreground hover:bg-accent",
            )}
          >
            All {vulns.length}
          </button>
          {SEVERITIES.filter((s) => counts[s] > 0).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSeverity(severity === s ? "all" : s)}
              aria-pressed={severity === s}
              className={cn(
                "rounded-lg border px-2.5 py-1 text-xs font-medium transition-all",
                SEVERITY_CLASS[s],
                severity !== s && severity !== "all" && "opacity-40",
                severity === s && "ring-2 ring-foreground/25",
              )}
            >
              {SEVERITY_LABEL[s]} {counts[s]}
            </button>
          ))}
        </div>
      </div>
      {data.length === 0 ? (
        <p className="rounded-2xl border border-dashed p-8 text-center text-sm text-muted-foreground">
          No CVEs match your filters.
        </p>
      ) : (
        <>
          <DataTable table={table} />
          <Pagination table={table} />
        </>
      )}
    </div>
  );
}
