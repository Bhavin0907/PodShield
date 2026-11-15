import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { type RulePatch, api } from "@/lib/api";

export const keys = {
  overview: ["overview"] as const,
  images: ["images"] as const,
  image: (id: string) => ["image", id] as const,
  scans: ["scans"] as const,
  scan: (id: number) => ["scan", id] as const,
  containers: ["containers"] as const,
  rules: ["rules"] as const,
  health: ["health"] as const,
};

export const useOverview = () => useQuery({ queryKey: keys.overview, queryFn: api.overview });
export const useImages = () => useQuery({ queryKey: keys.images, queryFn: api.images });
export const useImage = (id: string) => useQuery({ queryKey: keys.image(id), queryFn: () => api.image(id) });
export const useContainers = () => useQuery({ queryKey: keys.containers, queryFn: api.containers, retry: false });
export const useRules = () => useQuery({ queryKey: keys.rules, queryFn: api.rules });
export const useHealth = () =>
  useQuery({ queryKey: keys.health, queryFn: api.health, refetchInterval: 30_000, retry: false });

export const useScans = () =>
  useQuery({
    queryKey: keys.scans,
    queryFn: () => api.scans(100),
    // Keep the list live while something is in flight.
    refetchInterval: (query) =>
      query.state.data?.some((s) => s.status === "queued" || s.status === "running") ? 3000 : false,
  });

export const useScanDetail = (id: number, enabled: boolean) =>
  useQuery({ queryKey: keys.scan(id), queryFn: () => api.scan(id), enabled });

export function usePatchRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: RulePatch }) => api.patchRule(id, patch),
    onSuccess: (rule) => {
      qc.setQueryData(keys.rules, (old: import("@/lib/api").Rule[] | undefined) =>
        old?.map((r) => (r.id === rule.id ? rule : r)),
      );
    },
  });
}
