import { ChevronRight, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";

import { SeverityBadge } from "@/components/badges";
import { CodeBlock } from "@/components/code-block";
import { EmptyState } from "@/components/states";
import { Button } from "@/components/ui/button";
import type { Finding, Severity } from "@/lib/api";
import { SEVERITIES, SEVERITY_DOT, SEVERITY_LABEL } from "@/lib/constants";
import { cn } from "@/lib/utils";

const keyOf = (f: Finding, i: number) => `${f.rule_id}:${i}`;

export function FindingCard({ finding, open, onToggle }: { finding: Finding; open: boolean; onToggle: () => void }) {
  const panelId = `finding-${finding.rule_id}`;
  return (
    <div className={cn("rounded-xl border bg-card transition-colors", open && "border-border bg-card shadow-sm")}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={panelId}
        className="flex w-full items-center gap-3 rounded-xl px-4 py-3 text-left transition-colors hover:bg-accent/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <ChevronRight className={cn("size-4 shrink-0 text-muted-foreground transition-transform duration-200", open && "rotate-90")} />
        <SeverityBadge severity={finding.severity} />
        <span className="shrink-0 font-mono text-xs text-muted-foreground">{finding.rule_id}</span>
        <span className="min-w-0 flex-1 truncate text-sm font-medium">{finding.title}</span>
        {finding.evidence.length > 0 && (
          <span className="hidden shrink-0 text-xs text-muted-foreground sm:inline">
            {finding.evidence.length} evidence
          </span>
        )}
      </button>
      {open && (
        <div id={panelId} className="animate-fade-in space-y-4 border-t px-4 pb-4 pt-4 pl-11">
          <p className="text-sm leading-relaxed text-muted-foreground">{finding.description}</p>
          {finding.evidence.length > 0 && (
            <div>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Evidence</h4>
              <ul className="space-y-1 rounded-xl border bg-muted/30 p-3 font-mono text-xs">
                {finding.evidence.map((line, i) => (
                  <li key={i} className="break-all">
                    {line}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {finding.remediation && (
            <div>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Remediation</h4>
              <CodeBlock code={finding.remediation} title="Suggested fix" />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function FindingsList({ findings, emptyHint }: { findings: Finding[]; emptyHint?: string }) {
  const [open, setOpen] = useState<Set<string>>(() => new Set());

  const groups = useMemo(() => {
    const out = new Map<Severity, { finding: Finding; key: string }[]>();
    findings.forEach((f, i) => {
      const list = out.get(f.severity) ?? [];
      list.push({ finding: f, key: keyOf(f, i) });
      out.set(f.severity, list);
    });
    return out;
  }, [findings]);

  if (findings.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No findings"
        description={emptyHint ?? "Every enabled rule passed for this target."}
      />
    );
  }

  const allKeys = findings.map(keyOf);
  const allOpen = open.size === allKeys.length;
  const toggle = (key: string) =>
    setOpen((cur) => {
      const next = new Set(cur);
      if (!next.delete(key)) next.add(key);
      return next;
    });

  return (
    <div className="space-y-6">
      <div className="flex justify-end">
        <Button variant="ghost" size="sm" onClick={() => setOpen(allOpen ? new Set() : new Set(allKeys))}>
          {allOpen ? "Collapse all" : "Expand all"}
        </Button>
      </div>
      {SEVERITIES.filter((s) => groups.has(s)).map((s) => {
        const items = groups.get(s) ?? [];
        return (
          <section key={s} aria-label={`${SEVERITY_LABEL[s]} findings`}>
            <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
              <span className={cn("size-2.5 rounded-full", SEVERITY_DOT[s])} />
              {SEVERITY_LABEL[s]}
              <span className="font-normal text-muted-foreground">({items.length})</span>
            </h3>
            <div className="space-y-2">
              {items.map(({ finding, key }) => (
                <FindingCard key={key} finding={finding} open={open.has(key)} onToggle={() => toggle(key)} />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
