import type { Grade, Severity, SeverityCounts } from "@/lib/api";
import { GRADE_CLASS, SEVERITIES, SEVERITY_CLASS, SEVERITY_DOT, SEVERITY_LABEL } from "@/lib/constants";
import { cn } from "@/lib/utils";

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex min-w-[4.5rem] items-center justify-center rounded-md border px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide",
        SEVERITY_CLASS[severity],
        className,
      )}
    >
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function GradeBadge({ grade, size = "md" }: { grade: Grade | null; size?: "sm" | "md" | "lg" }) {
  const dims = { sm: "size-6 text-xs rounded-md", md: "size-8 text-sm rounded-lg", lg: "size-11 text-xl rounded-xl" }[size];
  if (!grade) {
    return (
      <span className={cn("inline-flex items-center justify-center border border-dashed text-muted-foreground", dims)}>?</span>
    );
  }
  return (
    <span
      className={cn("inline-flex items-center justify-center border font-bold", dims, GRADE_CLASS[grade])}
      aria-label={`Grade ${grade}`}
    >
      {grade}
    </span>
  );
}

/** Compact row of severity counts; zero counts are dimmed so non-zero ones stand out. */
export function SeverityCounters({
  counts,
  hideInfo = false,
  className,
}: {
  counts: SeverityCounts;
  hideInfo?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      {SEVERITIES.filter((s) => !(hideInfo && s === "info")).map((s) => (
        <span
          key={s}
          title={`${counts[s]} ${SEVERITY_LABEL[s].toLowerCase()}`}
          className={cn("flex items-center gap-1 text-xs tabular-nums", counts[s] === 0 && "opacity-35")}
        >
          <span className={cn("size-2 rounded-full", SEVERITY_DOT[s])} />
          {counts[s]}
        </span>
      ))}
    </div>
  );
}
