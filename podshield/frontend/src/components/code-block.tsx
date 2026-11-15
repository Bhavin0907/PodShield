import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { cn, copyText } from "@/lib/utils";

export function CopyButton({ text, label = "Copy", className }: { text: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    if (await copyText(text)) {
      setCopied(true);
      toast.success("Copied to clipboard");
      setTimeout(() => setCopied(false), 1800);
    } else {
      toast.error("Copy failed", { description: "Select the text and copy it manually." });
    }
  };
  return (
    <Button type="button" variant="ghost" size="sm" onClick={onCopy} className={cn("h-7 gap-1.5 px-2", className)}>
      {copied ? <Check className="text-primary" /> : <Copy />}
      <span className="text-xs">{copied ? "Copied" : label}</span>
    </Button>
  );
}

export function CodeBlock({
  code,
  title,
  className,
  maxHeight,
}: {
  code: string;
  title?: string;
  className?: string;
  maxHeight?: string;
}) {
  return (
    <div className={cn("overflow-hidden rounded-xl border bg-muted/40", className)}>
      <div className="flex items-center justify-between border-b bg-muted/50 px-3 py-1">
        <span className="font-mono text-[11px] uppercase tracking-wide text-muted-foreground">{title ?? "snippet"}</span>
        <CopyButton text={code} />
      </div>
      <pre
        className="overflow-auto p-3 font-mono text-xs leading-relaxed"
        style={maxHeight ? { maxHeight } : undefined}
        tabIndex={0}
      >
        <code>{code}</code>
      </pre>
    </div>
  );
}
