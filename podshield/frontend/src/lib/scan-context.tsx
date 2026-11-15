import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";

import {
  ApiError,
  type ProgressEvent,
  type ScanRequest,
  type ScanStatus,
  TERMINAL_STAGES,
  api,
} from "@/lib/api";

export interface ActiveScan {
  scanId: number;
  label: string;
  status: ScanStatus;
  current: number;
  total: number;
  image: string;
  message: string;
  log: ProgressEvent[];
  connectionLost: boolean;
}

interface ScanContextValue {
  scan: ActiveScan | null;
  busy: boolean;
  start: (request: ScanRequest, label: string) => Promise<void>;
  dismiss: () => void;
}

const ScanContext = createContext<ScanContextValue | null>(null);

const LOG_LIMIT = 40;

/** Pure reducer so the progress logic can be unit-tested without an EventSource. */
export function applyEvent(scan: ActiveScan, ev: ProgressEvent): ActiveScan {
  const next: ActiveScan = {
    ...scan,
    connectionLost: false,
    log: [...scan.log, ev].slice(-LOG_LIMIT),
  };
  switch (ev.stage) {
    case "queued":
      next.status = "queued";
      break;
    case "started":
      next.status = "running";
      break;
    case "image_started":
    case "image_done":
    case "image_failed":
      next.status = "running";
      next.current = ev.stage === "image_started" ? Math.max(0, ev.current - 1) : ev.current;
      next.total = ev.total;
      next.image = ev.image;
      break;
    case "completed":
    case "failed":
      next.status = ev.stage;
      next.current = ev.stage === "completed" ? ev.total : scan.current;
      next.total = ev.total || scan.total;
      break;
  }
  if (ev.message) next.message = ev.message;
  return next;
}

function newScan(scanId: number, label: string): ActiveScan {
  return {
    scanId,
    label,
    status: "queued",
    current: 0,
    total: 0,
    image: "",
    message: "",
    log: [],
    connectionLost: false,
  };
}

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient();
  const [scan, setScan] = useState<ActiveScan | null>(null);
  const scanId = scan?.scanId ?? null;
  const finishedRef = useRef<number | null>(null);

  // One EventSource per scan. The server replays buffered events on connect, so a page
  // reload or a late subscriber catches up automatically.
  useEffect(() => {
    if (scanId === null) return;
    const source = new EventSource(api.streamUrl(scanId));

    const onProgress = (e: MessageEvent<string>) => {
      let ev: ProgressEvent;
      try {
        ev = JSON.parse(e.data) as ProgressEvent;
      } catch {
        return;
      }
      setScan((cur) => (cur && cur.scanId === scanId ? applyEvent(cur, ev) : cur));
      if (TERMINAL_STAGES.has(ev.stage)) {
        source.close(); // otherwise EventSource would reconnect and replay forever
        if (finishedRef.current !== scanId) {
          finishedRef.current = scanId;
          void qc.invalidateQueries();
          if (ev.stage === "completed") toast.success("Scan complete", { description: "Results are up to date." });
          else toast.error("Scan failed", { description: ev.message || "See Scan History for details." });
        }
      }
    };
    const onError = () => setScan((cur) => (cur && cur.scanId === scanId ? { ...cur, connectionLost: true } : cur));

    source.addEventListener("progress", onProgress as EventListener);
    source.addEventListener("error", onError);
    return () => {
      source.removeEventListener("progress", onProgress as EventListener);
      source.removeEventListener("error", onError);
      source.close();
    };
  }, [scanId, qc]);

  // Attach to a scan that is already running (started from the CLI, the timer, or another tab).
  useEffect(() => {
    let cancelled = false;
    api
      .scans(5)
      .then((scans) => {
        const live = scans.find((s) => s.status === "queued" || s.status === "running");
        if (live && !cancelled) setScan((cur) => cur ?? newScan(live.id, live.target === "all" ? "All images" : live.target));
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  const start = useCallback(
    async (request: ScanRequest, label: string) => {
      try {
        const { scan_id } = await api.createScan(request);
        finishedRef.current = null;
        setScan(newScan(scan_id, label));
        void qc.invalidateQueries({ queryKey: ["scans"] });
      } catch (err) {
        toast.error("Could not start scan", { description: err instanceof ApiError ? err.message : String(err) });
      }
    },
    [qc],
  );

  const dismiss = useCallback(() => setScan(null), []);
  const busy = scan !== null && (scan.status === "queued" || scan.status === "running");
  const value = useMemo(() => ({ scan, busy, start, dismiss }), [scan, busy, start, dismiss]);
  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScan(): ScanContextValue {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScan must be used inside ScanProvider");
  return ctx;
}
