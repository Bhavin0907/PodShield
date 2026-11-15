import { type Header, type Table as TanTable, flexRender } from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

function SortHeader<T>({ header }: { header: Header<T, unknown> }) {
  const sorted = header.column.getIsSorted();
  if (header.isPlaceholder) return null;
  const content = flexRender(header.column.columnDef.header, header.getContext());
  if (!header.column.getCanSort()) return <>{content}</>;
  const Icon = sorted === "asc" ? ArrowUp : sorted === "desc" ? ArrowDown : ArrowUpDown;
  return (
    <button
      type="button"
      onClick={header.column.getToggleSortingHandler()}
      className={cn(
        "-ml-2 inline-flex items-center gap-1.5 rounded-md px-2 py-1 transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        sorted && "text-foreground",
      )}
    >
      {content}
      <Icon className={cn("size-3.5", !sorted && "opacity-40")} />
    </button>
  );
}

export function DataTable<T>({
  table,
  onRowClick,
  rowLabel,
  className,
}: {
  table: TanTable<T>;
  onRowClick?: (row: T) => void;
  rowLabel?: (row: T) => string;
  className?: string;
}) {
  return (
    <div className={cn("overflow-hidden rounded-2xl border bg-card", className)}>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id} className="border-b bg-muted/30 text-left text-xs font-medium text-muted-foreground">
                {hg.headers.map((h) => (
                  <th
                    key={h.id}
                    scope="col"
                    className="whitespace-nowrap px-3 py-2.5 first:pl-4 last:pr-4"
                    aria-sort={
                      h.column.getIsSorted() === "asc" ? "ascending" : h.column.getIsSorted() === "desc" ? "descending" : undefined
                    }
                  >
                    <SortHeader header={h} />
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody className="divide-y">
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                onKeyDown={
                  onRowClick
                    ? (e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          onRowClick(row.original);
                        }
                      }
                    : undefined
                }
                tabIndex={onRowClick ? 0 : undefined}
                aria-label={onRowClick && rowLabel ? rowLabel(row.original) : undefined}
                className={cn(
                  "transition-colors",
                  onRowClick && "cursor-pointer hover:bg-accent/50 focus-visible:bg-accent/60 focus-visible:outline-none",
                )}
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="whitespace-nowrap px-3 py-3 align-middle first:pl-4 last:pr-4">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function Pagination<T>({ table }: { table: TanTable<T> }) {
  const { pageIndex } = table.getState().pagination;
  const pages = table.getPageCount();
  if (pages <= 1) return null;
  return (
    <div className="flex items-center justify-between pt-3 text-xs text-muted-foreground">
      <span>
        Page {pageIndex + 1} of {pages}
      </span>
      <div className="flex gap-1">
        <Button variant="outline" size="sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>
          <ChevronLeft /> Prev
        </Button>
        <Button variant="outline" size="sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>
          Next <ChevronRight />
        </Button>
      </div>
    </div>
  );
}
