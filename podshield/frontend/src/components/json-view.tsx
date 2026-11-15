import { FileJson } from "lucide-react";
import { Fragment, useMemo } from "react";

import { CopyButton } from "@/components/code-block";
import { EmptyState } from "@/components/states";

const TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

/** Tiny JSON highlighter that builds React nodes (never injects HTML). */
export function highlightJson(text: string): React.ReactNode[] {
  const nodes: React.ReactNode[] = [];
  let last = 0;
  let n = 0;
  for (const m of text.matchAll(TOKEN)) {
    const start = m.index ?? 0;
    if (start > last) nodes.push(<Fragment key={n++}>{text.slice(last, start)}</Fragment>);
    const [full, str, colon, literal] = m;
    let cls = "text-sev-medium"; // numbers
    if (str) cls = colon ? "text-sky-500 dark:text-sky-400" : "text-emerald-600 dark:text-emerald-400";
    else if (literal) cls = "text-violet-500 dark:text-violet-400";
    nodes.push(
      <span key={n++} className={cls}>
        {str ?? full}
      </span>,
    );
    if (colon) nodes.push(<Fragment key={n++}>{colon}</Fragment>); // `full` = string + colon
    last = start + full.length;
  }
  if (last < text.length) nodes.push(<Fragment key={n++}>{text.slice(last)}</Fragment>);
  return nodes;
}

export function JsonView({ data, emptyHint }: { data: Record<string, unknown> | null; emptyHint?: string }) {
  const text = useMemo(() => (data ? JSON.stringify(data, null, 2) : ""), [data]);
  const nodes = useMemo(() => highlightJson(text), [text]);
  if (!data) {
    return (
      <EmptyState
        icon={FileJson}
        title="Configuration unavailable"
        description={emptyHint ?? "This image was scanned before configuration snapshots were stored. Rescan it to capture them."}
      />
    );
  }
  return (
    <div className="overflow-hidden rounded-2xl border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <p className="text-xs text-muted-foreground">Secret-looking values are masked (first 4 characters shown).</p>
        <CopyButton text={text} label="Copy JSON" />
      </div>
      <pre className="max-h-[32rem] overflow-auto p-4 font-mono text-xs leading-relaxed" tabIndex={0}>
        <code>{nodes}</code>
      </pre>
    </div>
  );
}
