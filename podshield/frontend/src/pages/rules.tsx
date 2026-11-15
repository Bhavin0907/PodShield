import { RotateCcw, Search, SlidersHorizontal } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { SeverityBadge } from "@/components/badges";
import { EmptyState, ErrorState, Notice, PageHeader, RowsSkeleton } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { ApiError, type Rule, type Severity } from "@/lib/api";
import { SEVERITIES, SEVERITY_LABEL } from "@/lib/constants";
import { usePatchRule, useRules } from "@/lib/queries";
import { cn } from "@/lib/utils";

export const isOverridden = (r: Rule): boolean => !r.enabled || r.severity !== r.default_severity;

function RuleRow({ rule }: { rule: Rule }) {
  const patch = usePatchRule();
  const pending = patch.isPending;

  const apply = (body: { enabled?: boolean | null; severity?: Severity | null }, message: string) =>
    patch.mutate(
      { id: rule.id, patch: body },
      {
        onSuccess: () => toast.success(`${rule.id}: ${message}`),
        onError: (err) => toast.error(`Could not update ${rule.id}`, { description: err instanceof ApiError ? err.message : String(err) }),
      },
    );

  return (
    <li className={cn("grid items-center gap-x-4 gap-y-3 px-5 py-4 transition-opacity md:grid-cols-[1fr_9.5rem_4rem]", !rule.enabled && "opacity-60")}>
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-muted-foreground">{rule.id}</span>
          <span className="text-sm font-medium">{rule.title}</span>
          {isOverridden(rule) && (
            <span className="rounded-md bg-sev-low/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-sev-low">Customized</span>
          )}
        </div>
        <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{rule.description}</p>
      </div>
      <div className="flex items-center gap-2">
        <Select
          value={rule.severity}
          disabled={pending}
          onValueChange={(v) => apply({ severity: v as Severity }, `severity set to ${v}`)}
        >
          <SelectTrigger aria-label={`Severity for ${rule.id}`}>
            <SelectValue>
              <SeverityBadge severity={rule.severity} className="min-w-0 border-0 bg-transparent p-0" />
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {SEVERITY_LABEL[s]}
                {s === rule.default_severity && <span className="ml-2 text-xs text-muted-foreground">default</span>}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="flex items-center justify-end gap-2">
        {isOverridden(rule) && (
          <Button
            variant="ghost"
            size="icon"
            className="size-8"
            disabled={pending}
            title="Reset to the config file value"
            aria-label={`Reset ${rule.id}`}
            onClick={() => apply({ enabled: null, severity: null }, "reset")}
          >
            <RotateCcw />
          </Button>
        )}
        <Switch
          checked={rule.enabled}
          disabled={pending}
          aria-label={`${rule.enabled ? "Disable" : "Enable"} ${rule.id}`}
          onCheckedChange={(checked) => apply({ enabled: checked }, checked ? "enabled" : "disabled")}
        />
      </div>
    </li>
  );
}

function Group({ title, description, rules }: { title: string; description: string; rules: Rule[] }) {
  if (rules.length === 0) return null;
  const enabled = rules.filter((r) => r.enabled).length;
  return (
    <section className="mb-8">
      <div className="mb-3 flex items-end justify-between">
        <div>
          <h2 className="text-base font-semibold">{title}</h2>
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <span className="text-xs text-muted-foreground">
          {enabled}/{rules.length} enabled
        </span>
      </div>
      <Card>
        <ul className="divide-y">
          {rules.map((r) => (
            <RuleRow key={r.id} rule={r} />
          ))}
        </ul>
      </Card>
    </section>
  );
}

export default function RulesPage() {
  const { data, isLoading, isError, error, refetch } = useRules();
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data ?? []).filter((r) => !q || r.id.toLowerCase().includes(q) || r.title.toLowerCase().includes(q));
  }, [data, query]);

  return (
    <>
      <PageHeader
        title="Rules"
        description="Turn checks on or off and change how severe they are. Changes are saved on the server and apply to every future scan, including scheduled ones."
        actions={
          <div className="relative w-64">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter rules" aria-label="Filter rules" className="pl-9" />
          </div>
        }
      />
      {isError ? (
        <ErrorState error={error} onRetry={() => void refetch()} title="Could not load rules" />
      ) : isLoading || !data ? (
        <RowsSkeleton rows={8} />
      ) : filtered.length === 0 ? (
        <EmptyState icon={SlidersHorizontal} title="No rules match" description="Try a different search term." />
      ) : (
        <>
          <div className="mb-6">
            <Notice title="Existing results are not rescored">
              Existing grades keep the rules that were active when they were scanned. Rescan an image to apply your changes.
            </Notice>
          </div>
          <Group title="Image hygiene" description="Evaluated for every image at scan time." rules={filtered.filter((r) => r.kind === "image")} />
          <Group title="Runtime" description="Evaluated for running containers." rules={filtered.filter((r) => r.kind === "runtime")} />
        </>
      )}
    </>
  );
}
