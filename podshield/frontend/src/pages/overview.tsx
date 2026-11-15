import { AlertOctagon, Boxes, Bug, ChevronRight, Gauge, ScanSearch } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from "recharts";

import { GradeBadge, SeverityCounters } from "@/components/badges";
import { CardGridSkeleton, EmptyState, ErrorState, PageHeader } from "@/components/states";
import { ScoreRing } from "@/components/score-ring";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { Overview } from "@/lib/api";
import { GRADES, GRADE_COLOR, SEVERITIES, SEVERITY_COLOR, SEVERITY_LABEL } from "@/lib/constants";
import { useOverview } from "@/lib/queries";
import { useScan } from "@/lib/scan-context";
import { cn, formatAge, timeAgo } from "@/lib/utils";

const AXIS = { fill: "hsl(var(--muted-foreground))", fontSize: 12 };
const TOOLTIP_STYLE: React.CSSProperties = {
  background: "hsl(var(--popover))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 12,
  fontSize: 12,
  color: "hsl(var(--popover-foreground))",
  boxShadow: "0 10px 30px -10px rgb(0 0 0 / 0.4)",
};

function Kpi({
  label,
  value,
  hint,
  icon: Icon,
  tone,
  children,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  icon: typeof Boxes;
  tone?: "danger";
  children?: React.ReactNode;
}) {
  return (
    <Card className="p-6 transition-shadow hover:shadow-md">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-muted-foreground">{label}</p>
          <p className={cn("mt-2 text-3xl font-semibold tabular-nums tracking-tight", tone === "danger" && "text-sev-critical")}>
            {value}
          </p>
          {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
        </div>
        {children ?? (
          <div className="flex size-10 items-center justify-center rounded-xl bg-muted text-muted-foreground">
            <Icon className="size-5" />
          </div>
        )}
      </div>
    </Card>
  );
}

function GradeChart({ data }: { data: Overview["grade_distribution"] }) {
  const rows = GRADES.map((g) => ({ grade: g, count: data[g] ?? 0 }));
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={rows} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke="hsl(var(--border))" strokeDasharray="3 3" />
        <XAxis dataKey="grade" tick={AXIS} axisLine={false} tickLine={false} />
        <YAxis allowDecimals={false} tick={AXIS} axisLine={false} tickLine={false} />
        <ChartTooltip
          cursor={{ fill: "hsl(var(--accent))" }}
          contentStyle={TOOLTIP_STYLE}
          formatter={(v: number) => [`${v} image${v === 1 ? "" : "s"}`, "Count"]}
          labelFormatter={(g: string) => `Grade ${g}`}
        />
        <Bar dataKey="count" radius={[8, 8, 0, 0]} maxBarSize={56}>
          {rows.map((r) => (
            <Cell key={r.grade} fill={GRADE_COLOR[r.grade]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function SeverityDonut({ overview }: { overview: Overview }) {
  const [mode, setMode] = useState<"findings" | "cves">("findings");
  const source = mode === "findings" ? overview.severity_totals : overview.cve_totals;
  const rows = SEVERITIES.map((s) => ({ severity: s, name: SEVERITY_LABEL[s], value: source[s] ?? 0 }));
  const total = rows.reduce((n, r) => n + r.value, 0);
  return (
    <>
      <div className="mb-2 flex gap-1 rounded-lg bg-muted p-1 text-xs font-medium" role="group" aria-label="Severity source">
        {(["findings", "cves"] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            aria-pressed={mode === m}
            className={cn(
              "flex-1 rounded-md px-3 py-1 capitalize transition-colors",
              mode === m ? "bg-card shadow-sm" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {m === "cves" ? "CVEs" : "Findings"}
          </button>
        ))}
      </div>
      {total === 0 ? (
        <div className="flex h-[188px] items-center justify-center text-sm text-muted-foreground">
          Nothing to show for {mode === "cves" ? "CVEs" : "findings"}.
        </div>
      ) : (
        <div className="relative">
          <ResponsiveContainer width="100%" height={188}>
            <PieChart>
              <ChartTooltip contentStyle={TOOLTIP_STYLE} />
              <Pie data={rows} dataKey="value" nameKey="name" innerRadius={58} outerRadius={82} paddingAngle={2} stroke="none">
                {rows.map((r) => (
                  <Cell key={r.severity} fill={SEVERITY_COLOR[r.severity]} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-semibold tabular-nums">{total}</span>
            <span className="text-xs text-muted-foreground">{mode === "cves" ? "CVEs" : "findings"}</span>
          </div>
        </div>
      )}
      <ul className="mt-2 flex flex-wrap justify-center gap-x-4 gap-y-1">
        {rows.map((r) => (
          <li key={r.severity} className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span className="size-2 rounded-full" style={{ background: SEVERITY_COLOR[r.severity] }} />
            {r.name} <span className="tabular-nums text-foreground">{r.value}</span>
          </li>
        ))}
      </ul>
    </>
  );
}

function TrendChart({ trend }: { trend: Overview["trend"] }) {
  const rows = useMemo(
    () =>
      trend.map((p) => ({
        label: new Date(p.at).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
        full: new Date(p.at).toLocaleString(),
        score: p.score,
      })),
    [trend],
  );
  if (rows.length === 0) {
    return <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">Run a scan to start the trend.</div>;
  }
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={rows} margin={{ top: 8, right: 12, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#10b981" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#10b981" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} stroke="hsl(var(--border))" strokeDasharray="3 3" />
        <XAxis dataKey="label" tick={AXIS} axisLine={false} tickLine={false} minTickGap={24} />
        <YAxis domain={[0, 100]} tick={AXIS} axisLine={false} tickLine={false} />
        <ChartTooltip
          contentStyle={TOOLTIP_STYLE}
          formatter={(v: number) => [v, "Fleet score"]}
          labelFormatter={(_l, payload) => (payload?.[0]?.payload as { full?: string } | undefined)?.full ?? ""}
        />
        <Area
          type="monotone"
          dataKey="score"
          stroke="#10b981"
          strokeWidth={2.5}
          fill="url(#trendFill)"
          dot={rows.length <= 12 ? { r: 3, fill: "#10b981", strokeWidth: 0 } : false}
          activeDot={{ r: 5 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function Riskiest({ items }: { items: Overview["riskiest"] }) {
  if (items.length === 0) return <p className="py-8 text-center text-sm text-muted-foreground">No images scanned yet.</p>;
  return (
    <ol className="divide-y">
      {items.map((img, i) => (
        <li key={img.id}>
          <Link
            to={`/images/${encodeURIComponent(img.id)}`}
            className="group flex items-center gap-4 rounded-xl px-2 py-3 transition-colors hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <span className="w-4 text-center text-xs tabular-nums text-muted-foreground">{i + 1}</span>
            <GradeBadge grade={img.grade} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium">{img.name}</p>
              <p className="truncate text-xs text-muted-foreground">
                {img.short_id} - {formatAge(img.age_days)} old
              </p>
            </div>
            <SeverityCounters counts={img.finding_counts} hideInfo className="hidden md:flex" />
            <span className="w-10 text-right text-sm font-semibold tabular-nums">{img.score ?? "-"}</span>
            <ChevronRight className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
          </Link>
        </li>
      ))}
    </ol>
  );
}

export default function OverviewPage() {
  const { data, isLoading, isError, error, refetch } = useOverview();
  const { start, busy } = useScan();

  if (isError) return <ErrorState error={error} onRetry={() => void refetch()} title="Could not load the overview" />;

  if (isLoading || !data) {
    return (
      <>
        <PageHeader title="Overview" description="Security posture of every image on this host." />
        <CardGridSkeleton />
        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-72 rounded-2xl" />
          ))}
        </div>
      </>
    );
  }

  if (data.images_audited === 0) {
    return (
      <>
        <PageHeader title="Overview" description="Security posture of every image on this host." />
        <EmptyState
          icon={ScanSearch}
          title="No images audited yet"
          description="Run your first scan to grade every local Podman image for hygiene issues, leaked secrets and known CVEs."
          action={
            <Button onClick={() => void start({ all: true }, "All images")} disabled={busy}>
              <ScanSearch /> Scan all images
            </Button>
          }
        />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Overview"
        description={`Security posture of every image on this host. Last scan ${timeAgo(data.last_scan_at)}.`}
      />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Images audited" value={data.images_audited} icon={Boxes} hint="Local Podman images" />
        <Kpi label="Fleet score" value={data.fleet_score ?? "-"} icon={Gauge} hint="Mean score across images">
          <ScoreRing score={data.fleet_score === null ? null : Math.round(data.fleet_score)} grade={data.fleet_grade} size={64} showGrade={false} />
        </Kpi>
        <Kpi
          label="Critical findings"
          value={data.critical_findings}
          icon={AlertOctagon}
          tone={data.critical_findings > 0 ? "danger" : undefined}
          hint={data.critical_findings > 0 ? "Fix these first" : "None. Nice."}
        />
        <Kpi label="CVEs" value={data.total_cves} icon={Bug} hint={`${data.cve_totals.critical} critical, ${data.cve_totals.high} high`} />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Grade distribution</CardTitle>
            <CardDescription>Images per grade</CardDescription>
          </CardHeader>
          <CardContent>
            <GradeChart data={data.grade_distribution} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Severity breakdown</CardTitle>
            <CardDescription>Across all images, latest scan</CardDescription>
          </CardHeader>
          <CardContent>
            <SeverityDonut overview={data} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Fleet score trend</CardTitle>
            <CardDescription>Mean score after each scan</CardDescription>
          </CardHeader>
          <CardContent>
            <TrendChart trend={data.trend} />
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader className="flex-row items-end justify-between">
          <div className="space-y-1">
            <CardTitle>Top 5 riskiest images</CardTitle>
            <CardDescription>Lowest scores first</CardDescription>
          </div>
          <Button asChild variant="ghost" size="sm">
            <Link to="/images">View all</Link>
          </Button>
        </CardHeader>
        <CardContent>
          <Riskiest items={data.riskiest} />
        </CardContent>
      </Card>
    </>
  );
}
