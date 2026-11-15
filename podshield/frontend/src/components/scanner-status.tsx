import { CheckCircle2, CircleSlash, Server } from "lucide-react";

import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { SCANNER_LABEL } from "@/lib/constants";
import { useHealth } from "@/lib/queries";
import { cn } from "@/lib/utils";

export function ScannerStatusList({ className }: { className?: string }) {
  const { data, isLoading, isError } = useHealth();
  if (isLoading) return <p className="text-sm text-muted-foreground">Checking scanners...</p>;
  if (isError || !data) return <p className="text-sm text-destructive">The API is not reachable.</p>;
  return (
    <ul className={cn("space-y-2.5", className)}>
      <li className="flex items-start gap-2.5 text-sm">
        {data.podman ? (
          <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" />
        ) : (
          <CircleSlash className="mt-0.5 size-4 shrink-0 text-destructive" />
        )}
        <div>
          <p className="font-medium">Podman socket</p>
          <p className="text-xs text-muted-foreground">
            {data.podman ? "Connected" : "Unreachable. Enable it with: systemctl enable --now podman.socket"}
          </p>
        </div>
      </li>
      {Object.entries(data.scanners).map(([name, s]) => (
        <li key={name} className="flex items-start gap-2.5 text-sm">
          {s.available ? (
            <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" />
          ) : (
            <CircleSlash className="mt-0.5 size-4 shrink-0 text-sev-medium" />
          )}
          <div className="min-w-0">
            <p className="font-medium">
              {SCANNER_LABEL[name] ?? name}
              {!s.enabled && <span className="ml-2 text-xs font-normal text-muted-foreground">(disabled in config)</span>}
            </p>
            <p className="break-words text-xs text-muted-foreground">{s.available ? "Available" : `Unavailable: ${s.detail}`}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}

export function ScannerStatusIndicator() {
  const { data, isError } = useHealth();
  const scanners = data ? Object.values(data.scanners).filter((s) => s.enabled) : [];
  const ok = scanners.filter((s) => s.available).length;
  const allGood = !isError && !!data && data.podman && ok === scanners.length;
  const down = isError || (data && !data.podman);
  const tone = down ? "bg-destructive" : allGood ? "bg-primary" : "bg-sev-medium";
  const label = isError ? "API offline" : !data ? "Checking" : `${ok}/${scanners.length} scanners`;

  return (
    <Popover>
      <PopoverTrigger
        className="flex h-9 items-center gap-2 rounded-xl border px-3 text-xs font-medium transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        aria-label={`Scanner availability: ${label}`}
      >
        <span className="relative flex size-2">
          {allGood && <span className={cn("absolute inline-flex size-full animate-ping rounded-full opacity-60", tone)} />}
          <span className={cn("relative inline-flex size-2 rounded-full", tone)} />
        </span>
        <Server className="size-3.5 text-muted-foreground" />
        <span className="hidden sm:inline">{label}</span>
      </PopoverTrigger>
      <PopoverContent>
        <h3 className="mb-3 text-sm font-semibold">Scanner availability</h3>
        <ScannerStatusList />
        <p className="mt-3 border-t pt-3 text-xs text-muted-foreground">
          Missing scanners are skipped. Results show which checks could not run.
        </p>
      </PopoverContent>
    </Popover>
  );
}
