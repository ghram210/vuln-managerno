import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { cn } from "@/lib/utils";

const severityColors: Record<string, string> = {
  Critical: "hsl(0 84% 60%)",
  High: "hsl(24 95% 53%)",
  Medium: "hsl(45 93% 47%)",
  Low: "hsl(142 71% 45%)",
  Info: "hsl(215 20% 65%)",
  None: "hsl(215 15% 75%)",
};

const statusColors: Record<string, string> = {
  Open: "hsl(0 84% 60%)",
  "In Progress": "hsl(35 92% 50%)",
  Closed: "hsl(142 71% 45%)",
  Suppressed: "hsl(215 20% 65%)",
};

const exploitColors: Record<string, string> = {
  "Actively Used": "hsl(0 84% 60%)",
  Available: "hsl(24 95% 53%)",
  Unproven: "hsl(45 93% 47%)",
  None: "hsl(215 20% 65%)",
};

const VulnDashboard = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [filterAsset, setFilterAsset] = useState("all");
  const [showAssetDrop, setShowAssetDrop] = useState(false);

  // Fetch unique assets/targets
  const { data: assets } = useQuery({
    queryKey: ["vuln-assets"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_rating_overview_filtered" as any).select("target");
      const uniqueTargets = Array.from(new Set((data || []).map((f: any) => f.target).filter(Boolean))) as string[];
      return uniqueTargets.sort();
    },
  });

  const { data: rawRatings } = useQuery({
    queryKey: ["vuln-ratings"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_rating_overview_filtered" as any).select("*").order("sort_order");
      return (data || []) as any[];
    },
  });

  const { data: statuses } = useQuery({
    queryKey: ["vuln-statuses"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_status_overview").select("*").order("sort_order");
      return data || [];
    },
  });

  const { data: daily } = useQuery({
    queryKey: ["vuln-daily", filterAsset],
    queryFn: async () => {
      // For now, daily trend stays global or we'd need target column in that view too
      const { data } = await supabase.from("vuln_daily_open").select("*").order("day");
      return data || [];
    },
  });

  const { data: riskScores } = useQuery({
    queryKey: ["vuln-risk"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_risk_score").select("*").order("sort_order");
      return data || [];
    },
  });

  const { data: topAssets } = useQuery({
    queryKey: ["vuln-top-assets"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_top_assets").select("*");
      return data || [];
    },
  });

  const { data: rawByTool } = useQuery({
    queryKey: ["vuln-by-tool"],
    queryFn: async () => {
      const { data } = await supabase.from("vuln_by_tool").select("*");
      return data || [];
    },
  });

  const { data: rawRemOpen } = useQuery({
    queryKey: ["remediation-open"],
    queryFn: async () => {
      const { data } = await supabase.from("remediation_open_filtered" as any).select("*").order("sort_order");
      return (data || []) as any[];
    },
  });

  const { data: remClosed } = useQuery({
    queryKey: ["remediation-closed"],
    queryFn: async () => {
      // remediation_closed is global for now
      return [];
    },
  });

  // Client-side aggregation/filtering logic
  const ratings = (rawRatings || []).filter(r => filterAsset === "all" || r.target === filterAsset);
  const aggregatedRatings = filterAsset === "all"
    ? ["Critical", "High", "Medium", "Low"].map(label => {
        const matching = ratings.filter(r => r.label === label);
        const val = matching.reduce((s, r) => s + r.value, 0);
        return { label, value: val, color: severityColors[label], id: label };
      })
    : ratings;

  const totalResults = aggregatedRatings.reduce((s, r) => s + r.value, 0);
  const ratingsWithPercent = aggregatedRatings.map(r => ({
    ...r,
    percentage: totalResults === 0 ? 0 : Math.round((r.value / totalResults) * 100)
  }));

  const byTool = (rawByTool || []).filter(t => filterAsset === "all" || t.target === filterAsset);
  const aggregatedByTool = filterAsset === "all"
    ? Array.from(new Set((rawByTool || []).map(t => t.label))).map(label => {
        const matching = byTool.filter(t => t.label === label);
        const val = matching.reduce((s, t) => s + t.value, 0);
        const color = (rawByTool || []).find(t => t.label === label)?.color || "hsl(215 20% 65%)";
        return { label, value: val, color, id: label };
      })
    : byTool;

  const remOpen = (rawRemOpen || []).filter(r => filterAsset === "all" || r.target === filterAsset);
  const aggregatedRemOpen = filterAsset === "all"
    ? ["Critical", "High", "Medium", "Low"].map(rating => {
        const matching = remOpen.filter(r => r.rating === rating);
        const total = matching.length;
        if (total === 0) return { rating, in_compliance: 100, not_in_compliance: 0, time_frame: "last_30_days", id: rating, color: severityColors[rating] };
        const avgComp = Math.round(matching.reduce((s, r) => s + (r.in_compliance || 0), 0) / total);
        return { rating, in_compliance: avgComp, not_in_compliance: 100 - avgComp, time_frame: "last_30_days", id: rating, color: severityColors[rating] };
      })
    : remOpen.map(r => ({ ...r, in_compliance: r.in_compliance || 0, not_in_compliance: r.not_in_compliance || 0 }));

  const totalRisk = (riskScores || []).reduce((s, r) => s + r.value, 0);

  const closeAllDrops = () => { setShowAssetDrop(false); };

  return (
    <div className="flex h-screen bg-background text-foreground">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="vuln-dashboard" />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6">
          {/* Tabs */}
          <div className="flex gap-1 mb-4">
            <button className="px-4 py-2 text-sm rounded-t-lg bg-card border border-border border-b-0 text-primary font-medium">
              Overview (CVSS)
            </button>
            <button className="px-4 py-2 text-sm rounded-t-lg text-muted-foreground hover:text-foreground">
              Overview (ExPRT rating)
            </button>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-4 mb-6">
            <span className="text-sm text-muted-foreground">Global Asset Filter:</span>

            {/* Asset filter */}
            <div className="relative">
              <button
                onClick={() => { closeAllDrops(); setShowAssetDrop(!showAssetDrop); }}
                className="flex items-center gap-2 px-3 py-1.5 text-sm bg-card border border-border rounded-lg min-w-[200px]"
              >
                <span className="truncate">{filterAsset === "all" ? "All Assets" : filterAsset}</span>
                <svg className="w-3 h-3 ml-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
              </button>
              {showAssetDrop && (
                <div className="absolute z-20 mt-1 bg-card border border-border rounded-lg shadow-lg py-1 min-w-[200px] max-h-60 overflow-y-auto">
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

            <span className="ml-auto text-sm text-muted-foreground">{totalResults.toLocaleString("en-US")} results</span>
          </div>

          {/* Rating Overview */}
          <h3 className="text-base font-semibold mb-1">Vulnerability Rating Overview</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Overview of the severity of discovered vulnerabilities based on the CVSS v3 standard.
          </p>
          <div className="grid grid-cols-4 gap-4 mb-8">
            {ratingsWithPercent.map((r) => {
              const color = severityColors[r.label] || r.color;
              return (
                <div key={r.id} className="bg-card border border-border rounded-xl p-4">
                  <div className="flex justify-between items-start mb-1">
                    <span className="text-sm font-medium" style={{ color }}>{r.label}</span>
                    <span className="text-xs text-muted-foreground">{r.percentage.toLocaleString("en-US")}%</span>
                  </div>
                  <p className="text-3xl font-bold mb-3" style={{ color }}>{r.value.toLocaleString("en-US")}</p>
                  <div className="h-1 rounded-full bg-muted">
                    <div className="h-1 rounded-full" style={{ width: `${r.percentage}%`, backgroundColor: color }} />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-2 gap-4 mb-8">
            <div className="bg-card border border-border rounded-xl p-5">
              <h3 className="text-sm font-semibold mb-4">Open vulnerabilities by day · Last 45 days</h3>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={daily || []}>
                  <XAxis dataKey="day" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} labelFormatter={(v) => `Day ${v}`} />
                  <Line type="monotone" dataKey="count" stroke="hsl(var(--primary))" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-card border border-border rounded-xl p-5">
              <h3 className="text-sm font-semibold mb-4">Risk Score · CVSS + Exploitability + Asset Criticality + Exposure</h3>
              <div className="flex flex-col items-center">
                <GaugeChart value={totalRisk} />
                <div className="flex flex-wrap gap-4 mt-4 justify-center">
                  {(riskScores || []).map((r) => {
                    const color = r.label === "Exploitability" ? "hsl(0 84% 60%)" : 
                                  r.label === "Asset Criticality" ? "hsl(270 70% 60%)" :
                                  r.label === "Exposure" ? "hsl(30 90% 55%)" : r.color;
                    return (
                      <div key={r.id} className="flex items-center gap-1.5 text-xs">
                        <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }} />
                        <span className="text-muted-foreground">{r.label}</span>
                        <span className="font-medium" style={{ color }}>{r.value.toLocaleString("en-US")}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          {/* Bar Charts Row */}
          <div className="grid grid-cols-2 gap-4 mb-8">
            <BarSection title="Top 5 At-Risk Assets" data={topAssets || []} />
            <BarSection title="Vulnerabilities by Discovery Tool" data={aggregatedByTool || []} />
          </div>

          {/* Remediation Compliance */}
          <div className="grid grid-cols-2 gap-4">
            <RemediationTable title="Remediation Time Frame Compliance (Open Vulnerabilities)" data={aggregatedRemOpen || []} colorMap={severityColors} />
            <RemediationTable title="Remediation Time Frame Compliance (Closed Vulnerabilities)" data={remClosed || []} colorMap={severityColors} />
          </div>
        </main>
      </div>
    </div>
  );
};

// Gauge Component - EASM Risk Score style matching reference image
const GaugeChart = ({ value }: { value: number }) => {
  const cx = 200;
  const cy = 170;
  const outerRadius = 140;
  const innerRadius = 100;

  const degToRad = (d: number) => (d * Math.PI) / 180;
  const valToAngle = (v: number) => 180 - (v / 100) * 180;

  const formatValue = (v: number) => v.toLocaleString("en-US");

  // Create thick arc segment using two arcs (outer + inner) forming a filled shape
  const arcSegment = (startVal: number, endVal: number) => {
    const a1 = degToRad(valToAngle(startVal));
    const a2 = degToRad(valToAngle(endVal));
    // Outer arc points
    const ox1 = cx + outerRadius * Math.cos(a1);
    const oy1 = cy - outerRadius * Math.sin(a1);
    const ox2 = cx + outerRadius * Math.cos(a2);
    const oy2 = cy - outerRadius * Math.sin(a2);
    // Inner arc points
    const ix1 = cx + innerRadius * Math.cos(a1);
    const iy1 = cy - innerRadius * Math.sin(a1);
    const ix2 = cx + innerRadius * Math.cos(a2);
    const iy2 = cy - innerRadius * Math.sin(a2);
    const largeArc = Math.abs(endVal - startVal) > 50 ? 1 : 0;
    return `M ${ox1} ${oy1} A ${outerRadius} ${outerRadius} 0 ${largeArc} 0 ${ox2} ${oy2} L ${ix2} ${iy2} A ${innerRadius} ${innerRadius} 0 ${largeArc} 1 ${ix1} ${iy1} Z`;
  };

  const segments = [
    { start: 0, end: 20, color: "#7dd3e8" },
    { start: 20, end: 40, color: "#4ade80" },
    { start: 40, end: 60, color: "#facc15" },
    { start: 60, end: 80, color: "#fb923c" },
    { start: 80, end: 100, color: "#ef4444" },
  ];

  const gap = 1.2;

  // Needle
  const needleAngle = degToRad(valToAngle(value));
  const needleLen = outerRadius - 8;
  const nx = cx + needleLen * Math.cos(needleAngle);
  const ny = cy - needleLen * Math.sin(needleAngle);

  return (
    <svg viewBox="0 0 400 230" className="w-80 h-48">
      {/* Arc segments - filled shapes with straight edges */}
      {segments.map((seg, i) => {
        const s = i === 0 ? seg.start : seg.start + gap / 2;
        const e = i === segments.length - 1 ? seg.end : seg.end - gap / 2;
        return (
          <path
            key={i}
            d={arcSegment(s, e)}
            fill={seg.color}
            stroke="none"
          />
        );
      })}
      {/* Tick labels */}
      {[0, 20, 40, 60, 80, 100].map((v) => {
        const a = degToRad(valToAngle(v));
        const labelR = outerRadius + 14;
        const tx = cx + labelR * Math.cos(a);
        const ty = cy - labelR * Math.sin(a);
        return (
          <text key={v} x={tx} y={ty} textAnchor="middle" dominantBaseline="central" fill="#94a3b8" fontSize={12} fontWeight={500}>
            {formatValue(v)}
          </text>
        );
      })}
      {/* Needle */}
      <line x1={cx} y1={cy} x2={nx} y2={ny} stroke="white" strokeWidth={2.5} strokeLinecap="round" />
      {/* Center circle */}
      <circle cx={cx} cy={cy} r={28} fill="none" stroke="#475569" strokeWidth={2} />
      <circle cx={cx} cy={cy} r={5} fill="white" />
      {/* Value below gauge */}
      <text x={cx} y={cy + 50} textAnchor="middle" dominantBaseline="central" fill="white" fontSize={32} fontWeight="bold">
        {formatValue(value)}
      </text>
    </svg>
  );
};

// Bar Section
const BarSection = ({ title, data, colorMap }: { title: string; data: Array<{ id: string; label: string; value: number; color: string }>; colorMap?: Record<string, string> }) => {
  const max = Math.max(...data.map((d) => d.value), 1);
  return (
    <div className="bg-card border border-border rounded-xl p-5">
      <h3 className="text-sm font-semibold mb-4">{title}</h3>
      <div className="space-y-3">
        {data.map((d) => {
          const color = colorMap?.[d.label] || d.color;
          return (
            <div key={d.id} className="flex items-center gap-3">
              <span className="text-sm w-28 shrink-0" style={{ color }}>{d.label}</span>
              <div className="flex-1 h-2.5 bg-muted rounded-full">
                <div className="h-2.5 rounded-full" style={{ width: `${(d.value / max) * 100}%`, backgroundColor: color }} />
              </div>
              <span className="text-sm font-medium w-8 text-right">{d.value.toLocaleString("en-US")}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

// Remediation Table
const RemediationTable = ({ title, data, colorMap }: { title: string; data: Array<{ id: string; rating: string; color: string; time_frame: string; in_compliance: number; not_in_compliance: number }>; colorMap?: Record<string, string> }) => {
  return (
    <div className="bg-card border border-border rounded-xl p-5">
      <h3 className="text-sm font-semibold mb-4">{title}</h3>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-muted-foreground text-xs uppercase tracking-wider">
            <th className="text-left py-2">ExPRT Rating</th>
            <th className="text-left py-2">Time Frame</th>
            <th className="text-left py-2">In Compliance</th>
            <th className="text-left py-2">Not In Compliance</th>
          </tr>
        </thead>
        <tbody>
          {data.map((row) => {
            const color = colorMap?.[row.rating] || row.color;
            return (
              <tr key={row.id} className="border-t border-border">
                <td className="py-3 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                  <span style={{ color }}>{row.rating}</span>
                </td>
                <td className="py-3 text-muted-foreground">{row.time_frame}</td>
                <td className="py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-20 h-2 bg-muted rounded-full">
                      <div className="h-2 rounded-full bg-green-500" style={{ width: `${row.in_compliance}%` }} />
                    </div>
                    <span className="text-green-400 text-xs">{row.in_compliance.toLocaleString("en-US")}%</span>
                  </div>
                </td>
                <td className="py-3">
                  <span className={`text-xs ${row.not_in_compliance > 0 ? "text-red-400" : "text-muted-foreground"}`}>
                    {row.not_in_compliance.toLocaleString("en-US")}%
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default VulnDashboard;
