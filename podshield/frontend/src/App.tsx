import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Suspense, lazy, useState } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster } from "sonner";

import { AppShell } from "@/components/app-shell";
import { Skeleton } from "@/components/ui/skeleton";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ApiError } from "@/lib/api";
import { ScanProvider } from "@/lib/scan-context";
import { ThemeProvider, useTheme } from "@/lib/theme";

// Overview is the landing page; the rest are split out to keep the first load small.
import OverviewPage from "@/pages/overview";
const ImagesPage = lazy(() => import("@/pages/images"));
const ImageDetailPage = lazy(() => import("@/pages/image-detail"));
const ContainersPage = lazy(() => import("@/pages/containers"));
const RegistryPage = lazy(() => import("@/pages/registry"));
const HistoryPage = lazy(() => import("@/pages/history"));
const RulesPage = lazy(() => import("@/pages/rules"));
const SettingsPage = lazy(() => import("@/pages/settings"));
const NotFoundPage = lazy(() => import("@/pages/not-found"));

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: true,
        // Do not hammer the API on 4xx; retry network blips once.
        retry: (count, error) => !(error instanceof ApiError && error.status >= 400 && error.status < 500) && count < 1,
      },
    },
  });
}

function ThemedToaster() {
  const { theme } = useTheme();
  return <Toaster theme={theme} position="top-right" richColors closeButton />;
}

const fallback = (
  <div className="space-y-4">
    <Skeleton className="h-8 w-48" />
    <Skeleton className="h-64 rounded-2xl" />
  </div>
);

export default function App() {
  const [client] = useState(makeQueryClient);
  return (
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <TooltipProvider delayDuration={200}>
          <BrowserRouter>
            <ScanProvider>
              <Suspense fallback={fallback}>
                <Routes>
                  <Route element={<AppShell />}>
                    <Route index element={<OverviewPage />} />
                    <Route path="images" element={<ImagesPage />} />
                    <Route path="images/:id" element={<ImageDetailPage />} />
                    <Route path="containers" element={<ContainersPage />} />
                    <Route path="registry" element={<RegistryPage />} />
                    <Route path="history" element={<HistoryPage />} />
                    <Route path="rules" element={<RulesPage />} />
                    <Route path="settings" element={<SettingsPage />} />
                    <Route path="*" element={<NotFoundPage />} />
                  </Route>
                </Routes>
              </Suspense>
              <ThemedToaster />
            </ScanProvider>
          </BrowserRouter>
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
