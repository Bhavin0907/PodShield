import { Layers as LayersIcon } from "lucide-react";
import { useState } from "react";

import { EmptyState } from "@/components/states";
import type { Layer } from "@/lib/api";
import { cn, formatBytes } from "@/lib/utils";

function LayerRow({ layer, index, max }: { layer: Layer; index: number; max: number }) {
  const [expanded, setExpanded] = useState(false);
  const pct = max > 0 && !layer.empty ? Math.max(1.5, (layer.size / max) * 100) : 0;
  const cmd = layer.created_by || "(no command recorded)";
  return (
    <li className="grid grid-cols-[2rem_1fr_5.5rem] items-start gap-3 px-4 py-3 sm:grid-cols-[2rem_1fr_12rem_5.5rem]">
      <span className="pt-0.5 font-mono text-xs text-muted-foreground">{index + 1}</span>
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
        title={expanded ? "Collapse" : "Show full command"}
        className={cn("min-w-0 text-left font-mono text-xs leading-relaxed", expanded ? "whitespace-pre-wrap break-all" : "truncate")}
      >
        {cmd}
      </button>
      <div className="mt-1.5 hidden h-2 overflow-hidden rounded-full bg-muted sm:block" aria-hidden>
        <div className="h-full rounded-full bg-primary transition-all duration-700" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-right text-xs tabular-nums text-muted-foreground">
        {layer.empty ? "empty" : formatBytes(layer.size)}
      </span>
    </li>
  );
}

export function LayersView({ layers }: { layers: Layer[] }) {
  if (layers.length === 0) {
    return (
      <EmptyState
        icon={LayersIcon}
        title="No layer history"
        description="This image does not expose build history, so layer sizes and commands are unavailable."
      />
    );
  }
  const max = Math.max(0, ...layers.map((l) => l.size));
  const total = layers.reduce((n, l) => n + l.size, 0);
  return (
    <div className="overflow-hidden rounded-2xl border bg-card">
      <div className="flex items-center justify-between border-b px-4 py-2.5 text-xs text-muted-foreground">
        <span>
          {layers.length} layers ({layers.filter((l) => !l.empty).length} with content)
        </span>
        <span className="tabular-nums">{formatBytes(total)} total</span>
      </div>
      <ol className="divide-y">
        {layers.map((layer, i) => (
          <LayerRow key={i} layer={layer} index={i} max={max} />
        ))}
      </ol>
    </div>
  );
}
