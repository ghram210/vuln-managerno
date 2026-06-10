import { useState, useMemo } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import {
  ChevronLeft,
  Search,
  ChevronDown,
  Wifi,
  Zap,
  UserCheck,
  MousePointer2,
  ShieldAlert,
  ArrowRight,
  Download,
  Eye,
  ExternalLink,
  ChevronRight
} from "lucide-react";
import { cn } from "@/lib/utils";

// --- Types ---

interface AttackVectorFinding {
  id: string;
  target: string;
  cve_id: string;
  severity: string;
  vector: string | null;
  score: number | null;
  av: string;
  ac: string;
  pr: string;
  ui: string;
  impact_c: { title: string; reason: string; status: "high" | "low" | "none" };
  impact_i: { title: string; reason: string; status: "high" | "low" | "none" };
  impact_a: { title: string; reason: string; status: "high" | "low" | "none" };
  exploit_status: "weaponized" | "theoretical";
  exploit_path: string | null;
}

// --- Helpers ---

const parseVector = (vector: string | null) => {
  const result = {
    av: "Unknown",
    ac: "Unknown",
    pr: "Unknown",
    ui: "Unknown",
    c: "N",
    i: "N",
    a: "N"
  };

  if (!vector) return result;

  const parts = vector.split("/");
  parts.forEach(part => {
    const [key, val] = part.split(":");
    if (key === "AV") {
      if (val === "N") result.av = "Network";
      else if (val === "A") result.av = "Adjacent";
      else if (val === "L") result.av = "Local";
      else if (val === "P") result.av = "Physical";
    } else if (key === "AC") {
      if (val === "L") result.ac = "Low";
      else if (val === "H") result.ac = "High";
    } else if (key === "PR") {
      if (val === "N") result.pr = "None";
      else if (val === "L") result.pr = "Low";
      else if (val === "H") result.pr = "High";
    } else if (key === "UI") {
      if (val === "N") result.ui = "None";
      else if (val === "R") result.ui = "Required";
    } else if (key === "C") result.c = val;
    else if (key === "I") result.i = val;
    else if (key === "A") result.a = val;
  });

  return result;
};

const getImpact = (type: "C" | "I" | "A", val: string) => {
  if (val === "H") {
    if (type === "C") return {
      title: "Data Leakage / تسريب بيانات كامل",
      reason: "Full unauthorized access to sensitive system information and user credentials.",
      status: "high" as const
    };
    if (type === "I") return {
      title: "Full Tampering / تخريب وتعديل كامل",
      reason: "The attacker can modify files, corrupt database tables, or execute unauthorized code leading to total integrity loss.",
      status: "high" as const
    };
    if (type === "A") return {
      title: "Denial of Service (DoS) / إيقاف الخدمة بالكامل",
      reason: "The attacker can crash the server, flood resources, or render the application entirely unavailable to users.",
      status: "high" as const
    };
  }
  if (val === "L") return { title: "Low Impact 🟡", reason: "Minor impact on this security pillar.", status: "low" as const };
  return { title: "No Impact 🟢", reason: "No significant impact detected.", status: "none" as const };
};

const AttackVector = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Filters
  const [search, setSearch] = useState("");
  const vectorFilter = searchParams.get("vector") || "all";
  const severityFilter = searchParams.get("severity") || "all";

  // --- Data Fetching ---

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ["attack_vector_data"],
    queryFn: async () => {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return [];

      // 1. Get latest scans for user (deduplicated by target/tool)
      const { data: scansRaw } = await supabase
        .from("scan_results")
        .select("id, target, tool, created_at")
        .eq("user_id", user.id)
        .order("created_at", { ascending: false });

      if (!scansRaw?.length) return [];

      // Deduplicate: latest scan per (target, tool)
      const dedup = new Map<string, string>();
      for (const s of scansRaw) {
        const key = `${s.target}||${(s.tool ?? "").toLowerCase().trim()}`;
        if (!dedup.has(key)) dedup.set(key, s.id);
      }
      const scanIds = [...dedup.values()];

      // 2. Get findings linked to these scans
      const { data: scanFindings } = await supabase
        .from("scan_findings")
        .select("id, target, severity, scan_id")
        .in("scan_id", scanIds);

      if (!scanFindings?.length) return [];
      const findingIds = scanFindings.map(f => f.id);

      // 3. Get CVE mapping
      const { data: findingCves } = await supabase
        .from("finding_cves")
        .select("finding_id, cve_id")
        .in("finding_id", findingIds);

      if (!findingCves?.length) return [];
      const cveIds = [...new Set(findingCves.map(fc => fc.cve_id))];

      // 4. Get CVE catalog and exploits
      const [{ data: catalog }, { data: exploits }] = await Promise.all([
        supabase.from("cve_catalog").select("*").in("cve_id", cveIds),
        supabase.from("exploits").select("*").in("cve_id", cveIds)
      ]);

      // 5. Map everything together
      return scanFindings.map(f => {
        const linkedCveIds = findingCves.filter(fc => fc.finding_id === f.id).map(fc => fc.cve_id);
        // For simplicity, we take the first CVE associated with the finding
        const cveId = linkedCveIds[0];
        const cveData = catalog?.find(c => c.cve_id === cveId);
        const exploitData = exploits?.find(e => e.cve_id === cveId);

        const vectorData = parseVector(cveData?.cvss_v3_vector || null);

        return {
          id: f.id,
          target: f.target,
          cve_id: cveId || "Non-CVE Finding",
          severity: f.severity || "info",
          vector: cveData?.cvss_v3_vector || null,
          score: cveData?.cvss_v3_score || null,
          av: vectorData.av,
          ac: vectorData.ac,
          pr: vectorData.pr,
          ui: vectorData.ui,
          impact_c: getImpact("C", vectorData.c),
          impact_i: getImpact("I", vectorData.i),
          impact_a: getImpact("A", vectorData.a),
          exploit_status: exploitData ? "weaponized" as const : "theoretical" as const,
          exploit_path: exploitData?.file_path || null
        };
      });
    }
  });

  // --- Filtered Data ---

  const filtered = useMemo(() => {
    return findings.filter(f => {
      const matchesSearch = !search ||
        f.cve_id.toLowerCase().includes(search.toLowerCase()) ||
        f.target.toLowerCase().includes(search.toLowerCase());

      const matchesVector = vectorFilter === "all" || f.av === vectorFilter;
      const matchesSeverity = severityFilter === "all" || f.severity.toLowerCase() === severityFilter.toLowerCase();

      return matchesSearch && matchesVector && matchesSeverity;
    });
  }, [findings, search, vectorFilter, severityFilter]);

  // --- Stats ---

  const stats = useMemo(() => {
    return {
      total: findings.length,
      network: findings.filter(f => f.av === "Network").length,
      adjacent: findings.filter(f => f.av === "Adjacent").length,
      local: findings.filter(f => f.av === "Local").length,
      physical: findings.filter(f => f.av === "Physical").length,
    };
  }, [findings]);

  return (
    <div className="flex h-screen bg-background text-foreground overflow-hidden">
      <AppSidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
        activePage="dashboard"
      />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* Header */}
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate("/")}
              className="p-2 rounded-lg border border-border hover:bg-accent transition-colors"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2">
              <Zap className="w-6 h-6 text-cyan-400" />
              <h1 className="text-2xl font-bold tracking-tight">Attack Vector Mapping</h1>
            </div>
          </div>

          {/* Top Cards */}
          <div className="grid grid-cols-5 gap-4">
            <StatCard label="TOTAL CVES" value={stats.total} color="text-foreground" />
            <StatCard label="NETWORK" value={stats.network} color="text-[#f43f7a]" /> {/* hsl(335 85% 60%) approx */}
            <StatCard label="ADJACENT" value={stats.adjacent} color="text-[#f87171]" /> {/* hsl(350 85% 65%) approx */}
            <StatCard label="LOCAL" value={stats.local} color="text-[#d946ef]" /> {/* hsl(315 80% 65%) approx */}
            <StatCard label="PHYSICAL" value={stats.physical} color="text-[#a855f7]" /> {/* hsl(290 70% 65%) approx */}
          </div>

          {/* Filters */}
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search CVE ID or target..."
                className="w-full bg-card border border-border rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/20"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            <SelectFilter
              value={vectorFilter}
              onChange={(v) => {
                const params = new URLSearchParams(searchParams);
                if (v === "all") params.delete("vector");
                else params.set("vector", v);
                setSearchParams(params);
              }}
              options={[
                { label: "All Vectors", value: "all" },
                { label: "Network", value: "Network" },
                { label: "Adjacent", value: "Adjacent" },
                { label: "Local", value: "Local" },
                { label: "Physical", value: "Physical" },
              ]}
            />

            <SelectFilter
              value={severityFilter}
              onChange={(v) => {
                const params = new URLSearchParams(searchParams);
                if (v === "all") params.delete("severity");
                else params.set("severity", v);
                setSearchParams(params);
              }}
              options={[
                { label: "All Severities", value: "all" },
                { label: "CRITICAL", value: "critical" },
                { label: "HIGH", value: "high" },
                { label: "MEDIUM", value: "medium" },
                { label: "LOW", value: "low" },
              ]}
            />

            <div className="ml-auto text-sm text-muted-foreground">
              {filtered.length} results
            </div>
          </div>

          {/* Table */}
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead>
                  <tr className="border-b border-border text-[11px] uppercase tracking-wider text-muted-foreground font-semibold">
                    <th className="px-6 py-4">Target / Asset</th>
                    <th className="px-6 py-4">Vulnerability</th>
                    <th className="px-6 py-4">CVSS Score</th>
                    <th className="px-6 py-4">Attack Vector</th>
                    <th className="px-6 py-4">Exploit Maturity</th>
                    <th className="px-6 py-4">Privileges Required</th>
                    <th className="px-6 py-4">User Interaction</th>
                    <th className="px-6 py-4"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {isLoading ? (
                    <tr>
                      <td colSpan={8} className="px-6 py-12 text-center text-muted-foreground">
                        Loading findings...
                      </td>
                    </tr>
                  ) : filtered.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-6 py-12 text-center text-muted-foreground">
                        No results found matching your filters.
                      </td>
                    </tr>
                  ) : (
                    filtered.map((f) => <FindingRow key={f.id} finding={f} />)
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </main>
      </div>
    </div>
  );
};

const StatCard = ({ label, value, color }: { label: string; value: number; color: string }) => (
  <div className="bg-card border border-border rounded-xl p-5">
    <div className="text-[10px] font-bold tracking-widest text-muted-foreground mb-1">{label}</div>
    <div className={cn("text-4xl font-bold", color)}>{value.toLocaleString()}</div>
  </div>
);

const SelectFilter = ({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { label: string; value: string }[] }) => (
  <div className="relative group">
    <select
      className="appearance-none bg-card border border-border rounded-lg pl-3 pr-10 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/20 cursor-pointer"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      {options.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
    </select>
    <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none group-hover:text-foreground transition-colors" />
  </div>
);

const FindingRow = ({ finding: f }: { finding: AttackVectorFinding }) => {
  const [expanded, setExpanded] = useState(false);
  const navigate = useNavigate();

  const scoreColors: any = {
    critical: "text-rose-500 border-rose-500/20 bg-rose-500/10",
    high: "text-orange-500 border-orange-500/20 bg-orange-500/10",
    medium: "text-amber-500 border-amber-500/20 bg-amber-500/10",
    low: "text-emerald-500 border-emerald-500/20 bg-emerald-500/10",
    info: "text-cyan-500 border-cyan-500/20 bg-cyan-500/10"
  };

  return (
    <>
      <tr
        className={cn(
          "hover:bg-accent/30 transition-colors cursor-pointer group",
          expanded && "bg-accent/30"
        )}
        onClick={() => setExpanded(!expanded)}
      >
        <td className="px-6 py-4 font-medium text-cyan-400 group-hover:underline">
          {f.target.replace(/^https?:\/\//, "")}
        </td>
        <td className="px-6 py-4">
          <button
            onClick={(e) => { e.stopPropagation(); navigate("/scan-results"); }}
            className="text-cyan-500 font-mono text-xs hover:underline"
          >
            {f.cve_id}
          </button>
        </td>
        <td className="px-6 py-4">
          {f.score !== null ? (
            <div className={cn("inline-flex items-center gap-1.5 px-2 py-1 rounded-md border text-[11px] font-bold tabular-nums", scoreColors[f.severity.toLowerCase()] || scoreColors.info)}>
              {f.score.toFixed(1)} {f.severity.toUpperCase()}
            </div>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </td>
        <td className="px-6 py-4 text-muted-foreground">
          {f.av === "Unknown" ? "—" : f.av}
        </td>
        <td className="px-6 py-4">
          {f.exploit_status === "weaponized" ? (
            <span className="flex items-center gap-1.5 text-orange-500 font-medium">
              <Zap className="w-3.5 h-3.5 fill-current" />
              Confirmed Exploit
            </span>
          ) : (
            <span className="text-muted-foreground/60">Theoretical / PoC Only</span>
          )}
        </td>
        <td className="px-6 py-4 text-muted-foreground">
          {f.pr === "Unknown" ? "—" : f.pr}
        </td>
        <td className="px-6 py-4 text-muted-foreground">
          {f.ui === "Unknown" ? "—" : f.ui}
        </td>
        <td className="px-6 py-4">
          <ChevronRight className={cn("w-4 h-4 text-muted-foreground transition-transform duration-200", expanded && "rotate-90")} />
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={8} className="px-6 py-6 bg-accent/10 border-t border-border/30">
            <div className="grid grid-cols-12 gap-6">

              {/* CIA Impact Details */}
              <div className="col-span-8 space-y-4">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-bold uppercase tracking-widest text-cyan-400">Security Impact Details (CIA)</span>
                </div>

                <div className="grid grid-cols-3 gap-4">
                  <ImpactBox title="Confidentiality" data={f.impact_c} />
                  <ImpactBox title="Integrity" data={f.impact_i} />
                  <ImpactBox title="Availability" data={f.impact_a} />
                </div>

                <div className="mt-4 p-4 rounded-lg bg-card/50 border border-border/50">
                  <div className="text-[11px] font-bold text-muted-foreground uppercase mb-2">Attack Metrics</div>
                  <div className="flex gap-8">
                    <div>
                      <div className="text-[10px] text-muted-foreground mb-1">Attack Complexity</div>
                      <div className="text-sm font-medium">{f.ac}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-muted-foreground mb-1">Privileges Required</div>
                      <div className="text-sm font-medium">{f.pr}</div>
                    </div>
                    <div>
                      <div className="text-[10px] text-muted-foreground mb-1">User Interaction</div>
                      <div className="text-sm font-medium">{f.ui}</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Actionable Exploit */}
              <div className="col-span-4 flex flex-col justify-between">
                <div>
                  <div className="text-xs font-bold uppercase tracking-widest text-orange-400 mb-3 flex items-center gap-2">
                    <Zap className="w-4 h-4" />
                    Actionable Exploit
                  </div>
                  <div className="p-4 rounded-xl border border-orange-500/20 bg-orange-500/5">
                    {f.exploit_status === "weaponized" ? (
                      <div className="space-y-3">
                        <div className="text-[13px] text-orange-200/90 leading-relaxed font-medium">
                          Functional Weaponized Script 🔥
                        </div>
                        <div className="text-[11px] text-orange-400/70 font-mono break-all">
                          {f.exploit_path}
                        </div>
                        <div className="flex gap-2">
                          <button className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-orange-500 hover:bg-orange-600 text-white rounded-lg text-xs font-bold transition-colors">
                            <Eye className="w-3.5 h-3.5" />
                            View Attack Script
                          </button>
                          <button className="p-2 border border-orange-500/30 hover:bg-orange-500/10 text-orange-400 rounded-lg transition-colors">
                            <Download className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-3 opacity-60">
                        <div className="text-[13px] text-muted-foreground font-medium italic">
                          Theoretical / PoC Only 📁
                        </div>
                        <p className="text-[11px] text-muted-foreground leading-relaxed">
                          No confirmed exploit code found in local Exploit-DB repository for this CVE.
                        </p>
                        <button className="w-full flex items-center justify-center gap-2 px-3 py-2 border border-border text-muted-foreground rounded-lg text-xs font-bold cursor-not-allowed">
                          <ExternalLink className="w-3.5 h-3.5" />
                          No Action Required
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>

            </div>
          </td>
        </tr>
      )}
    </>
  );
};

const ImpactBox = ({ title, data }: { title: string; data: any }) => (
  <div className={cn(
    "p-4 rounded-xl border transition-all",
    data.status === "high" ? "bg-rose-500/5 border-rose-500/20" :
    data.status === "low" ? "bg-amber-500/5 border-amber-500/20" :
    "bg-emerald-500/5 border-emerald-500/20"
  )}>
    <div className="text-[10px] font-bold uppercase text-muted-foreground mb-2">{title}</div>
    <div className={cn(
      "text-[12px] font-bold mb-1",
      data.status === "high" ? "text-rose-400" :
      data.status === "low" ? "text-amber-400" :
      "text-emerald-400"
    )}>
      {data.title}
    </div>
    <p className="text-[10px] text-muted-foreground leading-relaxed">
      {data.reason}
    </p>
  </div>
);

export default AttackVector;
