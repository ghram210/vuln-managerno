import { useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import {
  ArrowLeft,
  ShieldAlert,
  Activity,
  ChevronRight,
  ExternalLink,
  Target,
  Zap,
  Lock,
  Globe,
  Database,
  Search
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useChartAttackVector, useScanTargets } from "@/hooks/useAssetCharts";

// --- Types ---
interface AttackVectorDetail {
  id: string;
  cve_id: string;
  target: string;
  tool: string;
  severity: string;
  description: string;
  vector: string;
  impact_ar: string;
  remediation: string;
  exploit_url?: string;
  is_verified: boolean;
}

const AttackVector = () => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialVector = searchParams.get("vector") || "Network";
  const [selectedVector, setSelectedVector] = useState(initialVector);
  const [searchQuery, setSearchQuery] = useState("");

  const { data: chartData, isLoading: isChartLoading } = useChartAttackVector();
  const { data: targets } = useScanTargets();

  // Fetch detailed findings for the selected vector
  const { data: findings, isLoading: isFindingsLoading } = useQuery<AttackVectorDetail[]>({
    queryKey: ["attack_vector_details", selectedVector],
    queryFn: async () => {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return [];

      // 1. Get deduplicated scan results (latest scan per target/tool)
      // This matches the logic in useAssetCharts.ts to ensure consistent numbers
      const { data: scanRows } = await supabase
        .from("scan_results")
        .select("id, target, tool, created_at")
        .order("target")
        .order("tool")
        .order("created_at", { ascending: false });

      if (!scanRows?.length) return [];

      const dedupScanIds = new Set<string>();
      const seen = new Set<string>();
      for (const r of scanRows) {
        const key = `${r.target}||${(r.tool ?? "").toLowerCase().trim()}`;
        if (!seen.has(key)) {
          seen.add(key);
          dedupScanIds.add(r.id);
        }
      }

      // 2. Fetch findings for these deduplicated scans
      const { data: findingsRows } = await supabase
        .from("scan_findings")
        .select("id, target, tool, scan_id, severity, title")
        .in("scan_id", Array.from(dedupScanIds));

      if (!findingsRows?.length) return [];

      const findingIds = findingsRows.map(f => f.id);
      const { data: fcData } = await supabase
        .from("finding_cves")
        .select("finding_id, cve_id")
        .in("finding_id", findingIds);

      if (!fcData?.length) return [];

      const cveIds = [...new Set(fcData.map(r => r.cve_id))];
      const { data: cveRows } = await supabase
        .from("cve_catalog")
        .select("cve_id, cvss_v3_vector, description, cvss_v3_severity")
        .in("cve_id", cveIds);

      const results: AttackVectorDetail[] = [];

      for (const f of findingsRows) {
        const linkedCves = fcData.filter(r => r.finding_id === f.id).map(r => r.cve_id);
        if (linkedCves.length === 0) continue;

        const catalogMatch = cveRows?.find(c => linkedCves.includes(c.cve_id));
        if (!catalogMatch) continue;

        const vector = catalogMatch.cvss_v3_vector || "";
        const bucket = vector.includes("AV:N") ? "Network" :
                       vector.includes("AV:A") ? "Adjacent" :
                       vector.includes("AV:L") ? "Local" :
                       vector.includes("AV:P") ? "Physical" : "Unknown";

        if (bucket !== selectedVector) continue;

        // Arabic impact descriptions based on CVSS metrics
        let impactAr = "تأثير أمني مكتشف";
        if (vector.includes("C:H")) impactAr = "تسريب بيانات كامل وحساس";
        else if (vector.includes("C:L")) impactAr = "تسريب بيانات محدود";

        if (vector.includes("I:H")) impactAr += " + تعديل كامل في النظام";
        if (vector.includes("A:H")) impactAr += " + تعطيل كامل للخدمة";

        results.push({
          id: f.id,
          cve_id: linkedCves[0],
          target: f.target || "",
          tool: f.tool || "Scanner",
          severity: (catalogMatch.cvss_v3_severity || f.severity || "Low").toUpperCase(),
          description: catalogMatch.description || f.title || "No description available.",
          vector: vector,
          impact_ar: impactAr,
          remediation: "تحديث النظام إلى آخر إصدار وتطبيق التصحيحات الأمنية اللازمة.",
          is_verified: true
        });
      }

      return results;
    },
    staleTime: 60_000,
  });

  const filteredFindings = findings?.filter(f =>
    f.cve_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    f.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
    f.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <AppSidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        activePage="attack-vector"
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => navigate(-1)}
                className="p-2 rounded-lg hover:bg-secondary/80 transition-colors text-muted-foreground"
              >
                <ArrowLeft className="w-5 h-5" />
              </button>
              <div>
                <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
                  <ShieldAlert className="w-6 h-6 text-cyan-400" />
                  Attack Vector Analysis
                </h1>
                <p className="text-sm text-muted-foreground mt-1">
                  Deep dive into path-specific vulnerabilities and exploitation scenarios
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex bg-secondary/30 p-1 rounded-xl border border-border/50">
                {["Network", "Adjacent", "Local", "Physical"].map((v) => (
                  <button
                    key={v}
                    onClick={() => setSelectedVector(v)}
                    className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                      selectedVector === v
                        ? "bg-cyan-500/20 text-cyan-300 shadow-[0_0_15px_-3px_rgba(0,210,255,0.3)]"
                        : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                    }`}
                  >
                    {v}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Stats Bar */}
          <div className="grid grid-cols-4 gap-4">
            {chartData?.map((seg) => (
              <div
                key={seg.name}
                onClick={() => setSelectedVector(seg.name)}
                className={`p-4 rounded-2xl border transition-all cursor-pointer ${
                  selectedVector === seg.name
                    ? "bg-cyan-500/5 border-cyan-500/30 ring-1 ring-cyan-500/20"
                    : "bg-card border-border/40 hover:border-border/80"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{seg.name}</span>
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: seg.color }} />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-foreground">{seg.value}</span>
                  <span className="text-xs text-muted-foreground">Findings</span>
                </div>
              </div>
            ))}
          </div>

          {/* Filter & Search */}
          <div className="flex items-center gap-4 bg-card/50 p-4 rounded-2xl border border-border/30">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search by CVE, target, or description..."
                className="w-full bg-secondary/50 border-none rounded-xl pl-10 pr-4 py-2 text-sm focus:ring-1 focus:ring-cyan-500/50 outline-none"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <div className="h-8 w-[1px] bg-border/40" />
            <div className="flex items-center gap-2 text-xs text-muted-foreground px-2">
              <Target className="w-4 h-4" />
              <span>{targets?.length || 0} Assets Scanned</span>
            </div>
          </div>

          {/* Detailed Cards */}
          <div className="space-y-4 pb-12">
            {isFindingsLoading ? (
              <div className="flex flex-col items-center justify-center py-20 gap-4 opacity-50">
                <Activity className="w-8 h-8 text-cyan-400 animate-pulse" />
                <span className="text-sm font-medium">Analyzing findings...</span>
              </div>
            ) : filteredFindings?.length === 0 ? (
              <div className="text-center py-20 border-2 border-dashed border-border/30 rounded-3xl">
                <div className="w-16 h-16 bg-secondary/30 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Lock className="w-8 h-8 text-muted-foreground/30" />
                </div>
                <h3 className="text-lg font-semibold text-foreground">No Path Matches</h3>
                <p className="text-sm text-muted-foreground mt-1 max-w-sm mx-auto">
                  No vulnerabilities currently match the {selectedVector} attack vector criteria for your selected targets.
                </p>
              </div>
            ) : (
              filteredFindings?.map((f) => (
                <div
                  key={f.id}
                  className="group relative bg-card border border-border/40 rounded-3xl overflow-hidden hover:border-cyan-500/30 transition-all hover:shadow-[0_8px_30px_-12px_rgba(0,0,0,0.5)]"
                >
                  <div className="flex flex-col md:flex-row">
                    {/* Left Panel: Identity */}
                    <div className="md:w-72 p-6 border-b md:border-b-0 md:border-r border-border/30 bg-secondary/5">
                      <div className="flex items-center gap-2 mb-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          f.severity === "CRITICAL" ? "bg-red-500/20 text-red-400" :
                          f.severity === "HIGH" ? "bg-orange-500/20 text-orange-400" :
                          "bg-amber-500/20 text-amber-400"
                        }`}>
                          {f.severity}
                        </span>
                        <span className="text-[11px] font-mono text-muted-foreground">{f.cve_id}</span>
                      </div>

                      <div className="space-y-3">
                        <div className="flex items-start gap-3">
                          <Globe className="w-4 h-4 text-cyan-400/70 shrink-0 mt-0.5" />
                          <div className="min-w-0">
                            <p className="text-[10px] text-muted-foreground uppercase tracking-tight">Target</p>
                            <p className="text-xs font-mono font-medium truncate text-foreground">{f.target}</p>
                          </div>
                        </div>
                        <div className="flex items-start gap-3">
                          <Database className="w-4 h-4 text-purple-400/70 shrink-0 mt-0.5" />
                          <div>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-tight">Source Tool</p>
                            <p className="text-xs font-medium text-foreground capitalize">{f.tool}</p>
                          </div>
                        </div>
                      </div>

                      <div className="mt-8 pt-6 border-t border-border/20">
                        <div className="flex items-center gap-2 text-emerald-400">
                          <Zap className="w-3.5 h-3.5" />
                          <span className="text-[11px] font-bold uppercase tracking-widest">Actionable</span>
                        </div>
                      </div>
                    </div>

                    {/* Right Panel: Content */}
                    <div className="flex-1 p-6 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between mb-4">
                          <h3 className="font-bold text-lg text-foreground line-clamp-1 group-hover:text-cyan-300 transition-colors">
                            {f.description.split('.')[0]}.
                          </h3>
                          <button className="p-2 rounded-full hover:bg-secondary transition-colors opacity-0 group-hover:opacity-100">
                            <ExternalLink className="w-4 h-4 text-muted-foreground" />
                          </button>
                        </div>
                        <p className="text-sm text-muted-foreground/80 leading-relaxed mb-6">
                          {f.description}
                        </p>

                        <div className="grid grid-cols-2 gap-4">
                          <div className="p-3 rounded-2xl bg-secondary/20 border border-border/20">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                              <span className="text-[10px] font-bold text-muted-foreground uppercase">Impact (Arabic)</span>
                            </div>
                            <p className="text-sm font-semibold text-foreground text-right" dir="rtl">{f.impact_ar}</p>
                          </div>
                          <div className="p-3 rounded-2xl bg-secondary/20 border border-border/20">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                              <span className="text-[10px] font-bold text-muted-foreground uppercase">Recommended Fix</span>
                            </div>
                            <p className="text-sm font-semibold text-foreground text-right" dir="rtl">{f.remediation}</p>
                          </div>
                        </div>
                      </div>

                      <div className="mt-6 flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="flex items-center gap-1.5">
                            <Activity className="w-3.5 h-3.5 text-cyan-500" />
                            <span className="text-xs font-mono text-muted-foreground">{f.vector}</span>
                          </div>
                        </div>
                        <button className="flex items-center gap-2 text-xs font-bold text-cyan-400 hover:text-cyan-300 transition-colors uppercase tracking-widest group/btn">
                          Investigate Scenario
                          <ChevronRight className="w-4 h-4 group-hover/btn:translate-x-1 transition-transform" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </main>
      </div>
    </div>
  );
};

export default AttackVector;
