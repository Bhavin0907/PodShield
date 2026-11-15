import { ExternalLink, Moon, Sun } from "lucide-react";

import { PageHeader } from "@/components/states";
import { ScannerStatusList } from "@/components/scanner-status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useHealth } from "@/lib/queries";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const { data } = useHealth();

  return (
    <>
      <PageHeader title="Settings" description="Appearance and the state of this PodShield installation." />
      <div className="grid max-w-4xl grid-cols-1 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Appearance</CardTitle>
            <CardDescription>Dark is the default. Your choice is remembered in this browser.</CardDescription>
          </CardHeader>
          <CardContent className="flex gap-3">
            {(["dark", "light"] as const).map((t) => (
              <Button
                key={t}
                variant={theme === t ? "default" : "outline"}
                onClick={() => setTheme(t)}
                aria-pressed={theme === t}
                className="capitalize"
              >
                {t === "dark" ? <Moon /> : <Sun />} {t}
              </Button>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scanners</CardTitle>
            <CardDescription>
              Missing tools are skipped and flagged in results. Install them on the server, then restart the API service.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScannerStatusList />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>About</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <dl className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-y-2 sm:grid-cols-[8rem_minmax(0,1fr)]">
              <dt className="text-muted-foreground">Version</dt>
              <dd className="font-mono">{data?.version ?? "-"}</dd>
              <dt className="text-muted-foreground">Podman</dt>
              <dd className={cn(data?.podman ? "text-primary" : "text-destructive")}>{data ? (data.podman ? "Connected" : "Unreachable") : "-"}</dd>
              <dt className="text-muted-foreground">Configuration</dt>
              <dd className="break-all font-mono text-xs">/etc/podshield/config.toml</dd>
            </dl>
            <Button asChild variant="outline" size="sm">
              <a href="/api/docs" target="_blank" rel="noopener noreferrer">
                API documentation <ExternalLink />
              </a>
            </Button>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
