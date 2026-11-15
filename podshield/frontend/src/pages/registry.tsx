import { useMutation } from "@tanstack/react-query";
import { GlobeLock, History as HistoryIcon, Loader2, Search } from "lucide-react";
import { useState } from "react";

import { GradeBadge, SeverityCounters } from "@/components/badges";
import { ReportTabs } from "@/components/report-tabs";
import { ScoreRing } from "@/components/score-ring";
import { EmptyState, ErrorState, Notice, PageHeader } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError, type RegistryResult, type SeverityCounts, api } from "@/lib/api";
import { SEVERITIES } from "@/lib/constants";
import { formatBytes, formatDateTime } from "@/lib/utils";

const RECENT_KEY = "podshield-registry-recent";

function loadRecent(): string[] {
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(RECENT_KEY) ?? "[]");
    return Array.isArray(raw) ? raw.filter((r): r is string => typeof r === "string").slice(0, 5) : [];
  } catch {
    return [];
  }
}

function saveRecent(reference: string): string[] {
  const next = [reference, ...loadRecent().filter((r) => r !== reference)].slice(0, 5);
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {
    /* ignore */
  }
  return next;
}

export function countBySeverity(findings: RegistryResult["findings"]): SeverityCounts {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

function Result({ result }: { result: RegistryResult }) {
  return (
    <div className="animate-fade-in space-y-6">
      <Card className="p-6">
        <div className="flex flex-wrap items-center gap-6">
          <ScoreRing score={result.score} grade={result.grade} size={120} />
          <div className="min-w-0 flex-1 basis-64">
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="break-all text-xl font-semibold tracking-tight">{result.reference}</h2>
              <GradeBadge grade={result.grade} size="lg" />
            </div>
            <p className="mt-1 font-mono text-xs text-muted-foreground">{result.id.replace("sha256:", "").slice(0, 12)}</p>
            <dl className="mt-3 flex flex-wrap gap-x-8 gap-y-2 text-sm">
              <div>
                <dt className="text-xs text-muted-foreground">Compressed size</dt>
                <dd className="font-medium">{formatBytes(result.size)}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Created</dt>
                <dd className="font-medium">{formatDateTime(result.created)}</dd>
              </div>
            </dl>
            <SeverityCounters counts={countBySeverity(result.findings)} className="mt-3" />
          </div>
        </div>
      </Card>

      <div className="space-y-3">
        {result.notes.map((n) => (
          <Notice key={n} title={n} />
        ))}
        {result.skipped_rules.length > 0 && (
          <Notice tone="warn" title="Some rules need the image on disk">
            Not evaluated before pulling: <span className="font-mono">{result.skipped_rules.join(", ")}</span>. Pull the image and scan it
            for a complete audit.
          </Notice>
        )}
      </div>

      <ReportTabs
        findings={result.findings}
        layers={result.layers}
        config={result.config}
        findingsHint="No hygiene issues found in the image metadata."
      />
    </div>
  );
}

export default function RegistryPage() {
  const [reference, setReference] = useState("");
  const [recent, setRecent] = useState<string[]>(loadRecent);

  const audit = useMutation({
    mutationFn: (ref: string) => api.registryInspect(ref),
    onSuccess: (_data, ref) => setRecent(saveRecent(ref)),
  });

  const submit = (ref: string) => {
    const value = ref.trim();
    if (!value || audit.isPending) return;
    setReference(value);
    audit.mutate(value);
  };

  return (
    <>
      <PageHeader
        title="Registry Scan"
        description="Audit a remote image before pulling it. PodShield reads only the manifest and config via skopeo; nothing is downloaded or stored."
      />

      <Card className="mb-6 p-5">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit(reference);
          }}
          className="flex flex-col gap-3 sm:flex-row"
        >
          <div className="relative flex-1">
            <GlobeLock className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={reference}
              onChange={(e) => setReference(e.target.value)}
              placeholder="registry.access.redhat.com/ubi9/ubi-minimal:latest"
              aria-label="Remote image reference"
              spellCheck={false}
              autoComplete="off"
              className="h-11 pl-9 font-mono text-[13px]"
            />
          </div>
          <Button type="submit" size="lg" disabled={!reference.trim() || audit.isPending}>
            {audit.isPending ? <Loader2 className="animate-spin" /> : <Search />}
            {audit.isPending ? "Inspecting..." : "Audit image"}
          </Button>
        </form>
        {recent.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
            <span className="flex items-center gap-1 text-muted-foreground">
              <HistoryIcon className="size-3.5" /> Recent
            </span>
            {recent.map((r) => (
              <button
                key={r}
                type="button"
                onClick={() => submit(r)}
                className="max-w-full truncate rounded-lg border px-2.5 py-1 font-mono transition-colors hover:bg-accent"
              >
                {r}
              </button>
            ))}
          </div>
        )}
      </Card>

      {audit.isPending ? (
        <div className="space-y-4">
          <Skeleton className="h-40 rounded-2xl" />
          <Skeleton className="h-64 rounded-2xl" />
        </div>
      ) : audit.isError ? (
        <ErrorState
          error={audit.error}
          title={
            audit.error instanceof ApiError && audit.error.status === 503
              ? "Registry auditing is unavailable"
              : audit.error instanceof ApiError && audit.error.status === 422
                ? "That reference is not valid"
                : "Could not inspect the image"
          }
          onRetry={() => submit(reference)}
        />
      ) : audit.data ? (
        <Result result={audit.data} />
      ) : (
        <EmptyState
          icon={GlobeLock}
          title="Check an image before you pull it"
          description="Enter a reference like quay.io/org/app:1.2 to see its grade, hygiene findings, layers and config straight from the registry."
        />
      )}
    </>
  );
}
