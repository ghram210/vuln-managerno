import DonutChart from "@/components/DonutChart";
import { useChartView, type ChartViewName } from "@/hooks/useChartView";
import { useCveCatalogChart } from "@/hooks/useCveCatalogChart";
import { useAttackVectorChart } from "@/hooks/useAttackVectorChart";

interface DonutDef {
  view: ChartViewName;
  title: string;
  subtitle: string;
  centerLabel: string;
  emptyHint: string;
}

const DONUTS: DonutDef[] = [
  {
    view: "chart_findings_by_type",
    title: "Vulnerabilities by type",
    subtitle: "Findings grouped by detection category",
    centerLabel: "Findings",
    emptyHint:
      "No findings yet. Once any scan completes, results appear here split by tool category.",
  },
  {
    view: "chart_exploitability_risk",
    title: "Exploitability risk",
    subtitle: "Exploit potential of each matched CVE by severity",
    centerLabel: "CVEs",
    emptyHint:
      "No CVE matches yet. Once findings are correlated with NVD, exploit potential appears here.",
  },
  {
    view: "chart_asset_exposure",
    title: "Asset exposure",
    subtitle: "What types of assets are in your attack surface",
    centerLabel: "Assets",
    emptyHint:
      "No assets scanned yet. Run a scan and each target will be classified by type and location.",
  },
  {
    view: "chart_top_vulnerable_products",
    title: "Top vulnerable products",
    subtitle: "Products contributing the most CVEs across your scans",
    centerLabel: "Products",
    emptyHint:
      "No fingerprints yet. Detected vendor/product combinations from scans will rank here.",
  },
];

const CveCatalogCard = () => {
  const { data, isLoading } = useCveCatalogChart();
  return (
    <DonutChart
      title="Matched CVE Severity"
      subtitle="Severity distribution of CVEs found in your scans"
      centerLabel="CVEs"
      emptyHint="No CVE matches yet. Run a scan and results will be classified by severity."
      data={data ?? []}
      loading={isLoading}
    />
  );
};

const AttackVectorCard = () => {
  const { data, isLoading } = useAttackVectorChart();
  return (
    <DonutChart
      title="Attack Vectors"
      subtitle="How attackers can reach the vulnerabilities in your environment"
      centerLabel="CVEs"
      emptyHint="No vector data. Results appear once scans identify reachable vulnerabilities."
      data={data ?? []}
      loading={isLoading}
    />
  );
};

const DonutCard = ({ def }: { def: DonutDef }) => {
  const { data: result, isLoading } = useChartView(def.view);
  return (
    <DonutChart
      title={def.title}
      subtitle={def.subtitle}
      centerLabel={def.centerLabel}
      emptyHint={def.emptyHint}
      data={result?.data ?? []}
      loading={isLoading}
    />
  );
};

const DashboardDonuts = () => {
  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between">
        <h2 className="text-base font-semibold text-foreground">
          Risk overview
        </h2>
        <span className="text-[11px] text-muted-foreground/70">
          Computed live from your scan discoveries
        </span>
      </div>
      <div className="grid grid-cols-3 gap-4">
        <CveCatalogCard />
        {DONUTS.map((d) => (
          <DonutCard key={d.view} def={d} />
        ))}
        <AttackVectorCard />
      </div>
    </div>
  );
};

export default DashboardDonuts;
