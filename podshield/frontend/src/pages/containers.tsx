import { Box, Container as ContainerIcon, RefreshCw, ShieldCheck } from "lucide-react";
import { useState } from "react";

import { GradeBadge } from "@/components/badges";
import { FindingCard } from "@/components/findings-list";
import { ScoreRing } from "@/components/score-ring";
import { EmptyState, ErrorState, PageHeader } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError, type Container } from "@/lib/api";
import { SEVERITIES } from "@/lib/constants";
import { useContainers } from "@/lib/queries";
import { cn } from "@/lib/utils";

function ContainerCard({ container }: { container: Container }) {
  const [open, setOpen] = useState<Set<number>>(new Set());
  const toggle = (i: number) =>
    setOpen((cur) => {
      const next = new Set(cur);
      if (!next.delete(i)) next.add(i);
      return next;
    });
  const counts = SEVERITIES.map((s) => [s, container.findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0);

  return (
    <Card className="flex flex-col p-5 transition-shadow hover:shadow-md">
      <div className="flex items-start gap-4">
        <ScoreRing score={container.score} grade={container.grade} size={72} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className="truncate text-base font-semibold">{container.name}</h2>
            <GradeBadge grade={container.grade} size="sm" />
          </div>
          <p className="mt-0.5 truncate text-xs text-muted-foreground" title={container.image}>
            {container.image || "unknown image"}
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
            <span className="font-mono text-muted-foreground">{container.short_id}</span>
            <span
              className={cn(
                "rounded-md px-1.5 py-0.5 font-medium",
                container.status === "running" ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground",
              )}
            >
              {container.status || "unknown"}
            </span>
          </div>
        </div>
      </div>

      <div className="mt-4 flex-1 space-y-2">
        {container.findings.length === 0 ? (
          <p className="flex items-center gap-2 rounded-xl bg-primary/10 px-3 py-2.5 text-sm text-primary">
            <ShieldCheck className="size-4" /> No runtime issues found
          </p>
        ) : (
          <>
            <p className="text-xs text-muted-foreground">
              {counts.map(([s, n]) => `${n} ${s}`).join(", ")}
            </p>
            {container.findings.map((f, i) => (
              <FindingCard key={`${f.rule_id}-${i}`} finding={f} open={open.has(i)} onToggle={() => toggle(i)} />
            ))}
          </>
        )}
      </div>
    </Card>
  );
}

export default function ContainersPage() {
  const { data, isLoading, isError, error, refetch, isFetching } = useContainers();

  const refresh = (
    <Button variant="outline" onClick={() => void refetch()} disabled={isFetching}>
      <RefreshCw className={cn(isFetching && "animate-spin")} /> Refresh
    </Button>
  );

  return (
    <>
      <PageHeader
        title="Containers"
        description="Runtime posture of running containers: privileges, namespaces, capabilities and host mounts."
        actions={refresh}
      />
      {isError ? (
        <ErrorState
          error={error}
          onRetry={() => void refetch()}
          title={error instanceof ApiError && error.status === 503 ? "Podman is not reachable" : "Could not load containers"}
        />
      ) : isLoading || !data ? (
        <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {[0, 1, 2].map((i) => (
            <Skeleton key={i} className="h-56 rounded-2xl" />
          ))}
        </div>
      ) : data.length === 0 ? (
        <EmptyState
          icon={Box}
          title="No running containers"
          description="Start a container with podman run and it will be audited here against the runtime rules."
        />
      ) : (
        <div className="grid items-start gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {data.map((c) => (
            <ContainerCard key={c.id} container={c} />
          ))}
        </div>
      )}
      {data && data.length > 0 && (
        <p className="mt-4 flex items-center gap-1.5 text-xs text-muted-foreground">
          <ContainerIcon className="size-3.5" /> {data.length} running container{data.length === 1 ? "" : "s"}. Data is fetched live from Podman.
        </p>
      )}
    </>
  );
}
