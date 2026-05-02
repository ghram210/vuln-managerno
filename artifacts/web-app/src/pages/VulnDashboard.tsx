import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { cn } from "@/lib/utils";
import { Database } from "@/integrations/supabase/types";

type VulnRating = Database["public"]["Views"]["vuln_rating_overview_filtered"]["Row"];
type RemOpen = Database["public"]["Views"]["remediation_open_filtered"]["Row"];
type RemClosed = Database["public"]["Tables"]["remediation_closed"]["Row"];
type RiskScore = Database["public"]["Tables"]["vuln_risk_score"]["Row"];
type DailyTrend = Database["public"]["Tables"]["vuln_daily_open"]["Row"];
type TopAsset = Database["public"]["Views"]["vuln_top_assets"]["Row"];
type ByTool = Database["public"]["Views"]["vuln_by_tool"]["Row"];

const severityColors: Record<string, string> = {
  Critical: "hsl(0 84% 60%)",
  High: "hsl(24 95% 53%)",
  Medium: "hsl(45 93% 47%)",
  Low: "hsl(142 71% 45%)",
};

const VulnDashboard = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [filterAsset, setFilterAsset] = useState("all");
  const [showAssetDrop, setShowAssetDrop] = useState(false);

  // --- Data Fetching ---

  const { data: assets } = useQuery({
    queryKey: ["vuln-assets"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_rating_overview_filtered").select("target");
      const uniqueTargets = Array.from(new Set((data || []).map(f => f.target).filter(Boolean))) as string[];
      return uniqueTargets.sort();
    },
  });

  const { data: rawRatings } = useQuery({
    queryKey: ["vuln-ratings"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_rating_overview_filtered").select("*").order("sort_order");
      return (data || []) as VulnRating[];
    },
  });

  const { data: rawDaily } = useQuery({
    queryKey: ["vuln-daily", filterAsset],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_daily_open").select("*").order("day");
      return (data || []) as DailyTrend[];
    },
  });

  const { data: rawRiskScores } = useQuery({
    queryKey: ["vuln-risk", filterAsset],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_risk_score").select("*").order("sort_order");
      return (data || []) as RiskScore[];
    },
  });

  const { data: topAssets } = useQuery({
    queryKey: ["vuln-top-assets"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_top_assets").select("*");
      return (data || []) as TopAsset[];
    },
  });

  const { data: rawByTool } = useQuery({
    queryKey: ["vuln-by-tool"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_by_tool").select("*");
      return (data || []) as ByTool[];
    },
  });

  const { data: rawRemOpen } = useQuery({
    queryKey: ["remediation-open", filterAsset],
    queryFn: async () => {
      const { data } = await supabase.from("remediation_open_filtered").select("*").order("sort_order");
      return (data || []) as RemOpen[];
    },
  });

  const { data: rawRemClosed } = useQuery({
    queryKey: ["remediation-closed", filterAsset],
    queryFn: async () => {
      const { data } = await supabase.from("remediation_closed").select("*").order("sort_order");
      return (data || []) as RemClosed[];
    },
  });

  const { data: rawKPIs } = useQuery({
    queryKey: ["vuln-kpis", filterAsset],
    queryFn: async () => {
      const [mttr, weaponized, compliance] = await Promise.all([
        supabase.from("dash_kpi_mttr" as any).select("*"),
        supabase.from("dash_kpi_weaponized" as any).select("*"),
        supabase.from("dash_kpi_compliance" as any).select("*"),
      ]);
      return {
        mttr: (mttr.data || []) as any[],
        weaponized: (weaponized.data || []) as any[],
        compliance: (compliance.data || []) as any[],
      };
    },
  });

  // --- Aggregation Logic ---

  const daily = (rawDaily || []).filter(d => filterAsset === "all" || d.target === filterAsset);
  const aggregatedDaily = filterAsset === "all"
    ? Array.from(new Set(rawDaily?.map(d => d.day))).map(day => {
        const matching = rawDaily?.filter(d => d.day === day) || [];
        return { day, count: matching.reduce((s, d) => s + (d.count || 0), 0) };
      }).sort((a, b) => (a.day || 0) - (b.day || 0))
    : daily;

  const ratings = (rawRatings || []).filter(r => filterAsset === "all" || r.target === filterAsset);
  const aggregatedRatings = filterAsset === "all"
    ? ["Critical", "High", "Medium", "Low"].map(label => {
        const matching = ratings.filter(r => r.label === label);
        const val = matching.reduce((s, r) => s + (r.value || 0), 0);
        return { label, value: val, color: severityColors[label], id: label };
      })
    : ratings;

  const totalResults = aggregatedRatings.reduce((s, r) => s + (r.value || 0), 0);
  const ratingsWithPercent = aggregatedRatings.map(r => ({
    ...r,
    percentage: totalResults === 0 ? 0 : Math.round(((r.value || 0) / totalResults) * 100)
  }));

  const byTool = (rawByTool || []).filter(t => filterAsset === "all" || t.target === filterAsset);
  const aggregatedByTool = filterAsset === "all"
    ? Array.from(new Set((rawByTool || []).map(t => t.label))).map(label => {
        const matching = byTool.filter(t => t.label === label);
        const val = matching.reduce((s, t) => s + (t.value || 0), 0);
        const color = (rawByTool || []).find(t => t.label === label)?.color || "hsl(215 20% 65%)";
        return { label, value: val, color, id: label || "" };
      })
    : byTool.map(t => ({ ...t, id: t.id || "" }));

  const calculateRemediation = (rows: (RemOpen | RemClosed)[]) => {
    const filtered = rows.filter(r => filterAsset === "all" || r.target === filterAsset);
    return ["Critical", "High", "Medium", "Low"].map(rating => {
      const matching = filtered.filter(r => r.rating === rating);
      const totalCount = matching.reduce((s, r) => s + (r.total_count || 0), 0);
      const inCompCount = matching.reduce((s, r) => s + (r.in_comp_count || 0), 0);
      const inCompliance = totalCount === 0 ? 100 : Math.round((inCompCount / totalCount) * 100);
      return {
        rating,
        in_compliance: inCompliance,
        not_in_compliance: 100 - inCompliance,
        time_frame: "last_30_days",
        id: rating,
        color: severityColors[rating]
      };
    });
  };

  const aggregatedRemOpen = calculateRemediation(rawRemOpen || []);
  const aggregatedRemClosed = calculateRemediation(rawRemClosed || []);

  const riskScores = (rawRiskScores || []).filter(r => filterAsset === "all" || r.target === filterAsset);
  const aggregatedRiskScores = ["Base CVSS", "Exploitability", "Asset Criticality", "Exposure"].map(label => {
    const matching = riskScores.filter(r => r.label === label);
    const val = matching.reduce((s, r) => s + (r.value || 0), 0);
    const color = (rawRiskScores || []).find(r => r.label === label)?.color || "hsl(215 20% 65%)";
    return { label, value: val, color, id: label };
  });

  // Calculate weighted risk score for gauge (0-100 scale)
  // We sum the raw values and then normalize it.
  // In a real scenario, this would be a weighted average.
  // For the gauge, we use a heuristic based on total volume.
  const totalRiskVal = aggregatedRiskScores.reduce((s, r) => s + r.value, 0);
  const gaugeValue = filterAsset === "all"
    ? Math.min(100, Math.round(totalRiskVal / (Math.max(1, (assets?.length || 1)) * 10)))
    : Math.min(100, Math.round(totalRiskVal / 10));

  const kpis = {
    mttr: (rawKPIs?.mttr || []).filter(k => filterAsset === "all" || k.target === filterAsset).reduce((s, k) => s + (k.value || 0), 0),
    weaponized: (rawKPIs?.weaponized || []).filter(k => filterAsset === "all" || k.target === filterAsset).reduce((s, k) => s + (k.value || 0), 0),
    compliance: filterAsset === "all" ? Math.round(aggregatedRemOpen.reduce((s, r) => s + r.in_compliance, 0) / 4) : ((rawKPIs?.compliance || []).find(k => k.target === filterAsset)?.value || 0)
  };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="vuln-dashboard" />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6">
          {/* Header & Filter */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold">Vulnerability Dashboard</h1>
              <p className="text-muted-foreground text-sm">Security posture overview across all assets.</p>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-sm text-muted-foreground">Asset:</span>
              <div className="relative">
                <button
                  onClick={() => setShowAssetDrop(!showAssetDrop)}
                  className="flex items-center gap-2 px-3 py-1.5 text-sm bg-card border border-border rounded-lg min-w-[200px]"
                >
                  <span className="truncate">{filterAsset === "all" ? "All Assets" : filterAsset}</span>
                  <svg className="w-3 h-3 ml-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
                </button>
                {showAssetDrop && (
                  <div className="absolute z-20 mt-1 right-0 bg-card border border-border rounded-lg shadow-lg py-1 min-w-[200px] max-h-60 overflow-y-auto">
                    <button
                      onClick={() => { setFilterAsset("all"); setShowAssetDrop(false); }}
                      className={cn("w-full text-left px-3 py-1.5 text-sm hover:bg-accent", filterAsset === "all" ? "bg-primary text-primary-foreground" : "")}
                    >
                      All Assets {filterAsset === "all" && "✓"}
                    </button>
                    {(assets || []).map((asset) => (
                      <button
                        key={asset}
                        onClick={() => { setFilterAsset(asset); setShowAssetDrop(false); }}
                        className={cn("w-full text-left px-3 py-1.5 text-sm hover:bg-accent truncate", filterAsset === asset ? "bg-primary text-primary-foreground" : "")}
                      >
                        {asset} {filterAsset === asset && "✓"}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-3 gap-4 mb-8">
             <KPICard title="Mean Time To Remediate" value={kpis.mttr} unit="Days" color="hsl(190 65% 58%)" />
             <KPICard title="Weaponized Risks" value={kpis.weaponized} unit="Risks" color="hsl(355 70% 62%)" />
             <KPICard title="SLA Compliance" value={kpis.compliance} unit="%" color="hsl(155 50% 55%)" />
          </div>

          {/* Rating Overview */}
          <div className="mb-8">
            <h3 className="text-base font-semibold mb-1">Vulnerability Rating Overview</h3>
            <p className="text-sm text-muted-foreground mb-4">Severity breakdown based on CVSS v3 standard.</p>
            <div className="grid grid-cols-4 gap-4">
              {ratingsWithPercent.map((r) => {
                const color = severityColors[r.label || ""] || r.color;
                const descriptions: Record<string, string> = {
                  Critical: "Urgent: Direct threat to system security. Score 9.0-10.0.",
                  High: "Severe: Potential for significant data loss. Score 7.0-8.9.",
                  Medium: "Moderate: Exploitable under specific conditions. Score 4.0-6.9.",
                  Low: "Minor: Low impact or difficult to exploit. Score 0.1-3.9.",
                };
                return (
                  <div key={r.id} className="bg-card border border-border rounded-xl p-4 group relative">
                    <div className="flex justify-between items-start mb-1">
                      <span className="text-sm font-medium" style={{ color }}>{r.label}</span>
                      <span className="text-xs text-muted-foreground">{r.percentage}%</span>
                    </div>
                    <p className="text-3xl font-bold mb-3" style={{ color }}>{(r.value || 0).toLocaleString()}</p>
                    <div className="h-1 rounded-full bg-muted">
                      <div className="h-1 rounded-full" style={{ width: `${r.percentage}%`, backgroundColor: color }} />
                    </div>
                    <div className="absolute top-full left-0 mt-2 p-2 bg-popover text-popover-foreground text-[10px] rounded border border-border opacity-0 group-hover:opacity-100 transition-opacity z-10 w-full pointer-events-none shadow-xl">
                      {descriptions[r.label || ""]}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-2 gap-4 mb-8">
            <div className="bg-card border border-border rounded-xl p-5">
              <h3 className="text-sm font-semibold mb-4">Open vulnerabilities by day · Last 45 days</h3>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={aggregatedDaily}>
                  <XAxis dataKey="day" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                  <Line type="monotone" dataKey="count" stroke="hsl(var(--primary))" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-card border border-border rounded-xl p-5">
              <h3 className="text-sm font-semibold mb-4">Risk Score Breakdown</h3>
              <div className="flex flex-col items-center">
                <GaugeChart value={gaugeValue} />
                <div className="flex flex-wrap gap-4 mt-4 justify-center">
                  {aggregatedRiskScores.map((r) => (
                    <div key={r.id} className="flex items-center gap-1.5 text-xs">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: r.color }} />
                      <span className="text-muted-foreground">{r.label}</span>
                      <span className="font-medium" style={{ color: r.color }}>{r.value.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Bar Charts Row */}
          <div className="grid grid-cols-2 gap-4 mb-8">
            <BarSection title="Top 5 At-Risk Assets" data={topAssets || []} />
            <BarSection title="Vulnerabilities by Discovery Tool" data={aggregatedByTool} />
          </div>

          {/* Remediation Compliance */}
          <div className="grid grid-cols-2 gap-4">
            <RemediationTable title="Remediation Compliance (Open)" data={aggregatedRemOpen} colorMap={severityColors} />
            <RemediationTable title="Remediation Compliance (Closed)" data={aggregatedRemClosed} colorMap={severityColors} />
          </div>
        </main>
      </div>
    </div>
  );
};

const KPICard = ({ title, value, unit, color }: { title: string; value: number; unit: string; color: string }) => (
  <div className="bg-card border border-border rounded-xl p-5">
    <h4 className="text-muted-foreground text-xs font-medium uppercase tracking-wider mb-2">{title}</h4>
    <div className="flex items-baseline gap-2">
      <span className="text-3xl font-bold" style={{ color }}>{value.toLocaleString()}</span>
      <span className="text-muted-foreground text-sm">{unit}</span>
    </div>
  </div>
);

const GaugeChart = ({ value }: { value: number }) => {
  const cx = 200; const cy = 170; const outerRadius = 140; const innerRadius = 100;
  const valToAngle = (v: number) => 180 - (Math.min(v, 100) / 100) * 180;
  const degToRad = (d: number) => (d * Math.PI) / 180;

  const arcSegment = (startVal: number, endVal: number) => {
    const a1 = degToRad(valToAngle(startVal)); const a2 = degToRad(valToAngle(endVal));
    const ox1 = cx + outerRadius * Math.cos(a1); const oy1 = cy - outerRadius * Math.sin(a1);
    const ox2 = cx + outerRadius * Math.cos(a2); const oy2 = cy - outerRadius * Math.sin(a2);
    const ix1 = cx + innerRadius * Math.cos(a1); const iy1 = cy - innerRadius * Math.sin(a1);
    const ix2 = cx + innerRadius * Math.cos(a2); const iy2 = cy - innerRadius * Math.sin(a2);
    return `M ${ox1} ${oy1} A ${outerRadius} ${outerRadius} 0 0 0 ${ox2} ${oy2} L ${ix2} ${iy2} A ${innerRadius} ${innerRadius} 0 0 1 ${ix1} ${iy1} Z`;
  };

  const segments = [
    { start: 0, end: 20, color: "#7dd3e8" }, { start: 20, end: 40, color: "#4ade80" },
    { start: 40, end: 60, color: "#facc15" }, { start: 60, end: 80, color: "#fb923c" },
    { start: 80, end: 100, color: "#ef4444" },
  ];

  const needleAngle = degToRad(valToAngle(value));
  const nx = cx + (outerRadius - 10) * Math.cos(needleAngle);
  const ny = cy - (outerRadius - 10) * Math.sin(needleAngle);

  return (
    <svg viewBox="0 0 400 230" className="w-80 h-48">
      {segments.map((seg, i) => <path key={i} d={arcSegment(seg.start, seg.end)} fill={seg.color} />)}
      <line x1={cx} y1={cy} x2={nx} y2={ny} stroke="white" strokeWidth={2} />
      <circle cx={cx} cy={cy} r={6} fill="white" />
      <text x={cx} y={cy + 40} textAnchor="middle" fill="white" fontSize={32} fontWeight="bold">{Math.round(value)}</text>
    </svg>
  );
};

const BarSection = ({ title, data }: { title: string; data: any[] }) => {
  const max = Math.max(...data.map(d => d.value || 0), 1);
  return (
    <div className="bg-card border border-border rounded-xl p-5">
      <h3 className="text-sm font-semibold mb-4">{title}</h3>
      <div className="space-y-3">
        {data.map((d, i) => (
          <div key={i} className="flex items-center gap-3">
            <span className="text-xs w-28 truncate" style={{ color: d.color }}>{d.label}</span>
            <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
              <div className="h-full" style={{ width: `${((d.value || 0) / max) * 100}%`, backgroundColor: d.color }} />
            </div>
            <span className="text-xs font-medium w-8 text-right">{(d.value || 0).toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const RemediationTable = ({ title, data, colorMap }: { title: string; data: any[]; colorMap: any }) => (
  <div className="bg-card border border-border rounded-xl p-5">
    <h3 className="text-sm font-semibold mb-4">{title}</h3>
    <table className="w-full text-xs">
      <thead>
        <tr className="text-muted-foreground text-[10px] uppercase tracking-wider">
          <th className="text-left py-2">Rating</th>
          <th className="text-left py-2">Compliance</th>
          <th className="text-right py-2">Delta</th>
        </tr>
      </thead>
      <tbody>
        {data.map((row) => (
          <tr key={row.id} className="border-t border-border">
            <td className="py-3 flex items-center gap-2">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: colorMap[row.rating] }} />
              <span style={{ color: colorMap[row.rating] }}>{row.rating}</span>
            </td>
            <td className="py-3">
              <div className="flex items-center gap-2">
                <div className="w-20 h-1.5 bg-muted rounded-full">
                  <div className="h-full bg-green-500 rounded-full" style={{ width: `${row.in_compliance}%` }} />
                </div>
                <span>{row.in_compliance}%</span>
              </div>
            </td>
            <td className="py-3 text-right text-muted-foreground">0%</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

export default VulnDashboard;
