import { FindingsList } from "@/components/findings-list";
import { JsonView } from "@/components/json-view";
import { LayersView } from "@/components/layers-view";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { VulnsTable } from "@/components/vulns-table";
import type { Finding, Layer, Vulnerability } from "@/lib/api";

function Count({ n }: { n: number }) {
  return <span className="rounded-md bg-foreground/10 px-1.5 text-xs tabular-nums">{n}</span>;
}

/** The Findings / CVEs / Layers / Config tabs, shared by image detail and registry scan. */
export function ReportTabs({
  findings,
  vulnerabilities,
  layers,
  config,
  cveNote,
  findingsHint,
  configHint,
}: {
  findings: Finding[];
  vulnerabilities?: Vulnerability[]; // omitted for registry audits (no CVE data before pulling)
  layers: Layer[];
  config: Record<string, unknown> | null;
  cveNote?: string;
  findingsHint?: string;
  configHint?: string;
}) {
  return (
    <Tabs defaultValue="findings">
      <TabsList>
        <TabsTrigger value="findings">
          Findings <Count n={findings.length} />
        </TabsTrigger>
        {vulnerabilities && (
          <TabsTrigger value="cves">
            CVEs <Count n={vulnerabilities.length} />
          </TabsTrigger>
        )}
        <TabsTrigger value="layers">
          Layers <Count n={layers.length} />
        </TabsTrigger>
        <TabsTrigger value="config">Config</TabsTrigger>
      </TabsList>
      <TabsContent value="findings">
        <FindingsList findings={findings} emptyHint={findingsHint} />
      </TabsContent>
      {vulnerabilities && (
        <TabsContent value="cves">
          <VulnsTable vulns={vulnerabilities} unavailableNote={cveNote} />
        </TabsContent>
      )}
      <TabsContent value="layers">
        <LayersView layers={layers} />
      </TabsContent>
      <TabsContent value="config">
        <JsonView data={config} emptyHint={configHint} />
      </TabsContent>
    </Tabs>
  );
}
