import { useState, useMemo, Fragment } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import { ArrowLeft, Download, Eye, Shield, Wifi, ChevronDown, ChevronUp, User, Lock } from "lucide-react";
import { cn } from "@/lib/utils";

type ImpactLevel = "N" | "L" | "H";
type AVCode = "N" | "A" | "L" | "P";

function parseVector(vec: string | null) {
  if (!vec) return null;
  const get = (key: string) => {
    const m = vec.match(new RegExp(`/${key}:([^/]+)`));
    return m ? m[1] : null;
  };
  return {
    av: get("AV") as AVCode | null,
    ac: get("AC"),
    pr: get("PR"),
    ui: get("UI"),
    c:  get("C") as ImpactLevel | null,
    i:  get("I") as ImpactLevel | null,
    a:  get("A") as ImpactLevel | null,
  };
}

const AV_LABEL: Record<string, { label: string; color: string; bg: string }> = {
  N: { label: "Network",  color: "text-red-400",    bg: "bg-red-500/15 border-red-500/30" },
  A: { label: "Adjacent", color: "text-orange-400", bg: "bg-orange-500/15 border-orange-500/30" },
  L: { label: "Local",    color: "text-yellow-400", bg: "bg-yellow-500/15 border-yellow-500/30" },
  P: { label: "Physical", color: "text-green-400",  bg: "bg-green-500/15 border-green-500/30" },
};

const PR_META: Record<string, { label: string; color: string; bg: string; title: string }> = {
  N: { label: "None", color: "text-red-400",    bg: "bg-red-500/15 border-red-500/30",    title: "No privileges needed — any unauthenticated attacker can exploit" },
  L: { label: "Low",  color: "text-orange-400", bg: "bg-orange-500/15 border-orange-500/30", title: "Low-level account required (e.g. basic user)" },
  H: { label: "High", color: "text-green-400",  bg: "bg-green-500/15 border-green-500/30",  title: "Admin / elevated privileges required to exploit" },
};

const UI_META: Record<string, { label: string; color: string; bg: string; title: string }> = {
  N: { label: "None",     color: "text-red-400",    bg: "bg-red-500/15 border-red-500/30",    title: "No user interaction required — attacker exploits autonomously. Extremely dangerous." },
  R: { label: "Required", color: "text-yellow-400", bg: "bg-yellow-500/15 border-yellow-500/30", title: "User must perform an action (e.g. click a link, open a file) — typical of XSS, CSRF, phishing." },
};

function isWeaponizedScript(file: string | null): boolean {
  if (!file) return false;
  const lower = file.toLowerCase();
  return lower.endsWith(".py") || lower.endsWith(".rb");
}

function buildCIAReason(description: string | null, code: ImpactLevel | null, type: "C" | "I" | "A"): string {
  const desc = (description ?? "").toLowerCase();
  const firstSentence = (description ?? "").split(/[.!?\n]/)[0]?.trim() ?? "";
  const ctx = firstSentence.length > 25
    ? `${firstSentence.charAt(0).toUpperCase()}${firstSentence.slice(1)}.`
    : null;

  if (code === "H") {
    if (type === "C") {
      if (desc.includes("password") || desc.includes("credential") || desc.includes("authentication"))
        return ctx ? `${ctx} Exposes user passwords or authentication credentials, enabling account takeover.` : "Exposes user passwords or authentication credentials, enabling account takeover.";
      if (desc.includes("session") || desc.includes("cookie") || desc.includes("token"))
        return ctx ? `${ctx} Leaks session tokens or cookies, allowing session hijacking.` : "Leaks session tokens or cookies, allowing an attacker to hijack authenticated sessions.";
      if (desc.includes("sql") || desc.includes("database"))
        return ctx ? `${ctx} Unauthorized read access to all database records.` : "SQL exposure allows unauthorized read access to all stored database records.";
      if (desc.includes("path traversal") || desc.includes("directory traversal") || desc.includes("arbitrary file read"))
        return ctx ? `${ctx} Allows reading arbitrary files including configuration and private keys.` : "Path traversal allows reading arbitrary server files including configuration and sensitive data.";
      if (desc.includes("source code") || desc.includes("source-code"))
        return ctx ? `${ctx} Application source code is exposed, revealing logic and hardcoded secrets.` : "Exposes application source code, revealing business logic and hardcoded secrets.";
      if (desc.includes("memory") || desc.includes("heap") || desc.includes("stack dump"))
        return ctx ? `${ctx} Memory disclosure leaks runtime secrets and sensitive process data.` : "Memory disclosure leaks process data including keys, secrets, or sensitive runtime information.";
      if (desc.includes("information disclosure") || desc.includes("disclose") || desc.includes("expose") || desc.includes("read"))
        return ctx ? `${ctx} Full information disclosure — unauthorized read access to sensitive system data.` : "Full information disclosure — attacker gains unauthorized read access to sensitive system data.";
      return ctx ? `${ctx} Full confidentiality breach — sensitive data can be read by an attacker.` : "Full unauthorized read access to sensitive data and system information.";
    }
    if (type === "I") {
      if (desc.includes("sql injection") || desc.includes("sqli"))
        return ctx ? `${ctx} SQL injection allows inserting, modifying, or deleting backend database records.` : "SQL injection allows inserting, modifying, or deleting records in the backend database.";
      if (desc.includes("command injection") || desc.includes("os command") || desc.includes("remote code") || desc.includes("code execution") || desc.includes(" rce"))
        return ctx ? `${ctx} Remote code execution grants full write control — any file can be modified or overwritten.` : "Remote code or command execution grants full write access — attacker can modify any file or run arbitrary commands.";
      if (desc.includes("file upload") || desc.includes("arbitrary upload") || desc.includes("unrestricted upload"))
        return ctx ? `${ctx} Unrestricted file upload enables deploying webshells or malicious scripts.` : "Unrestricted file upload allows deploying malicious scripts (webshells) directly to the server.";
      if (desc.includes("xss") || desc.includes("cross-site script") || desc.includes("script injection"))
        return ctx ? `${ctx} Injected scripts can silently alter page content or DOM-stored data.` : "Injected scripts can silently modify page content, redirect users, or alter DOM-stored data.";
      if (desc.includes("csrf") || desc.includes("cross-site request"))
        return ctx ? `${ctx} CSRF forces authenticated users to perform unintended state-changing actions.` : "CSRF forces authenticated users to perform unintended state-changing actions without their knowledge.";
      if (desc.includes("overwrite") || desc.includes("write") || desc.includes("modify") || desc.includes("tamper"))
        return ctx ? `${ctx} Critical configuration files, database entries, or application data can be overwritten.` : "Attacker can overwrite critical configuration files, database entries, or application data.";
      return ctx ? `${ctx} Full integrity impact — data, files, or configuration can be altered by an attacker.` : "Attacker can modify or corrupt files, database records, or application configuration.";
    }
    if (desc.includes("denial of service") || desc.includes("dos attack") || desc.includes("distributed denial"))
      return ctx ? `${ctx} Remote denial-of-service crashes or makes the service completely unavailable.` : "Remote denial-of-service attack crashes or makes the service completely unavailable to users.";
    if (desc.includes("null pointer") || desc.includes("null dereference"))
      return ctx ? `${ctx} Null pointer dereference causes an immediate process crash.` : "Null pointer dereference causes an immediate process crash, taking down the service.";
    if (desc.includes("memory exhaustion") || desc.includes("out of memory") || desc.includes("resource exhaustion") || desc.includes("memory leak"))
      return ctx ? `${ctx} Memory exhaustion forces the server to become unresponsive under load.` : "Memory or resource exhaustion forces the server to become unresponsive or crash under load.";
    if (desc.includes("infinite loop") || desc.includes("cpu exhaustion") || desc.includes("cpu usage"))
      return ctx ? `${ctx} Infinite loop or CPU spike can freeze the server process.` : "Infinite loop or CPU spike can freeze the server process, causing complete downtime.";
    if (desc.includes("buffer overflow") || desc.includes("stack overflow") || desc.includes("heap overflow"))
      return ctx ? `${ctx} Buffer overflow triggers an application crash or DoS condition.` : "Buffer overflow triggers an application crash, potentially rendering the service unavailable.";
    if (desc.includes("crash") || desc.includes("abort") || desc.includes("segfault") || desc.includes("segmentation"))
      return ctx ? `${ctx} Exploiting this vulnerability causes the application to crash and stop serving requests.` : "Exploiting this vulnerability causes the application to crash and stop serving requests.";
    return ctx ? `${ctx} Full availability impact — service can be rendered completely unavailable.` : "Attacker can crash the server or exhaust resources, causing complete service unavailability.";
  }

  if (code === "L") {
    if (type === "C") return ctx ? `${ctx} Partial data exposure — attacker reads a limited subset, not full system access.` : "Partial information disclosure — attacker can read a limited subset of data, not full system access.";
    if (type === "I") return ctx ? `${ctx} Limited write impact — only a restricted portion of data or files can be modified.` : "Limited write access — attacker can alter only a restricted portion of data or files.";
    return ctx ? `${ctx} Reduced service performance or partial degradation, but no complete outage.` : "Reduced performance or partial service degradation, but no complete outage.";
  }

  if (type === "C") return "No confidentiality impact — this vulnerability does not expose sensitive information.";
  if (type === "I") return "No integrity impact — data and files remain unmodified by this vulnerability.";
  return "No availability impact — the service remains fully operational.";
}

function impactDetails(description: string | null, code: ImpactLevel | null, type: "C" | "I" | "A") {
  if (code === "H") return {
    badge: type === "C" ? "🔴 Data Leakage / تسريب كامل" : type === "I" ? "🔴 Full Tampering / تخريب كامل" : "🔴 DoS / إيقاف الخدمة",
    reason: buildCIAReason(description, code, type),
    color: "text-red-400", bg: "bg-red-500/10 border-red-500/20",
  };
  if (code === "L") return {
    badge: "🟡 Low Impact",
    reason: buildCIAReason(description, code, type),
    color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20",
  };
  return {
    badge: "🟢 No Impact",
    reason: buildCIAReason(description, code, type),
    color: "text-green-400", bg: "bg-green-500/10 border-green-500/20",
  };
}

interface Row {
  target: string;
  cve_id: string;
  cvss_v3_score: number | null;
  cvss_v3_severity: string | null;
  cvss_v3_vector: string | null;
  description: string | null;
  exploit_edb_id: number | null;
  exploit_file: string | null;
  exploit_verified: boolean | null;
}

const ExpandedCIA = ({ parsed, description }: { parsed: ReturnType<typeof parseVector>; description: string | null }) => {
  if (!parsed) return null;
  const metrics: { label: string; code: ImpactLevel | null; type: "C" | "I" | "A" }[] = [
    { label: "Confidentiality", code: parsed.c, type: "C" },
    { label: "Integrity",       code: parsed.i, type: "I" },
    { label: "Availability",    code: parsed.a, type: "A" },
  ];
  return (
    <div className="space-y-2">
      {metrics.map(({ label, code, type }) => {
        const d = impactDetails(description, code, type);
        return (
          <div key={type} className={`rounded-lg border px-3 py-2 ${d.bg}`}>
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">{label}</span>
              <span className={`text-[11px] font-semibold ${d.color}`}>{d.badge}</span>
            </div>
            <p className="text-[11px] text-muted-foreground leading-snug">{d.reason}</p>
          </div>
        );
      })}
    </div>
  );
};

const ScoreBadge = ({ score, severity }: { score: number | null; severity: string | null }) => {
  const sev = (severity ?? "").toUpperCase();
  const colorMap: Record<string, string> = {
    CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
    HIGH:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
    MEDIUM:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    LOW:      "bg-green-500/20 text-green-400 border-green-500/30",
  };
  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-bold",
      colorMap[sev] || "bg-muted/30 text-muted-foreground border-border/30"
    )}>
      {score?.toFixed(1) ?? "—"}
      <span className="font-normal opacity-70">{sev || "N/A"}</span>
    </span>
  );
};

const AttackVectorPage = () => {
  const navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [filterAV, setFilterAV] = useState("all");
  const [filterSev, setFilterSev] = useState("all");
  const [search, setSearch] = useState("");

  const { data: rows = [], isLoading, refetch } = useQuery<Row[]>({
    queryKey: ["attack-vector-page"],
    staleTime: 0,
    queryFn: async () => {
      const { data, error } = await (supabase as any)
        .from("scan_findings")
        .select(`
          target,
          finding_cves!inner(
            cve_id,
            cve_catalog!inner(
              cve_id, cvss_v3_score, cvss_v3_severity, cvss_v3_vector, description
            )
          )
        `)
        .order("created_at", { ascending: false });

      if (error) throw error;

      const map = new Map<string, Row>();
      for (const f of (data ?? [])) {
        for (const fc of (f.finding_cves ?? [])) {
          const c = fc.cve_catalog;
          if (!c?.cve_id) continue;
          const key = `${f.target}::${c.cve_id}`;
          if (!map.has(key)) {
            map.set(key, {
              target: f.target,
              cve_id: c.cve_id,
              cvss_v3_score: c.cvss_v3_score,
              cvss_v3_severity: c.cvss_v3_severity,
              cvss_v3_vector: c.cvss_v3_vector,
              description: c.description,
              exploit_edb_id: null,
              exploit_file: null,
              exploit_verified: null,
            });
          }
        }
      }

      const baseRows = Array.from(map.values());
      if (baseRows.length === 0) return [];

      const cveIds = [...new Set(baseRows.map(r => r.cve_id))];
      const { data: exploits } = await (supabase as any)
        .from("exploits")
        .select("cve_id, exploit_db_id, file_path, verified")
        .in("cve_id", cveIds);

      const exploitMap = new Map<string, { edbId: number; file: string | null; verified: boolean }>();
      for (const e of (exploits ?? [])) {
        if (e.cve_id && !exploitMap.has(e.cve_id)) {
          exploitMap.set(e.cve_id, { edbId: e.exploit_db_id, file: e.file_path, verified: e.verified });
        }
      }

      return baseRows.map(r => ({
        ...r,
        exploit_edb_id: exploitMap.get(r.cve_id)?.edbId ?? null,
        exploit_file: exploitMap.get(r.cve_id)?.file ?? null,
        exploit_verified: exploitMap.get(r.cve_id)?.verified ?? null,
      })).sort((a, b) => (b.cvss_v3_score ?? 0) - (a.cvss_v3_score ?? 0));
    },
  });

  const filtered = useMemo(() => {
    return rows.filter(r => {
      const parsed = parseVector(r.cvss_v3_vector);
      if (filterAV !== "all" && parsed?.av !== filterAV) return false;
      if (filterSev !== "all" && (r.cvss_v3_severity ?? "").toUpperCase() !== filterSev) return false;
      if (search) {
        const q = search.toLowerCase();
        if (!r.cve_id.toLowerCase().includes(q) && !r.target.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [rows, filterAV, filterSev, search]);

  const toggleRow = (key: string) => {
    setExpandedRows(prev => {
      const n = new Set(prev);
      n.has(key) ? n.delete(key) : n.add(key);
      return n;
    });
  };

  const stats = useMemo(() => {
    const avCount: Record<string, number> = {};
    let weaponized = 0;
    for (const r of rows) {
      const p = parseVector(r.cvss_v3_vector);
      const av = AV_LABEL[p?.av ?? ""]?.label ?? "Unknown";
      avCount[av] = (avCount[av] ?? 0) + 1;
      if (isWeaponizedScript(r.exploit_file)) weaponized++;
    }
    return { avCount, weaponized, total: rows.length };
  }, [rows]);

  return (
    <div className="flex h-screen bg-background text-foreground">
      <AppSidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} activePage="attack-vector" />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-6">

          {/* Header */}
          <div className="flex items-center gap-4 mb-6">
            <button
              onClick={() => navigate("/")}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Assets Dashboard
            </button>
            <span className="text-border">/</span>
            <div className="flex items-center gap-2">
              <Wifi className="w-5 h-5 text-primary" />
              <h1 className="text-2xl font-bold">Attack Vector Mapping</h1>
            </div>
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-5 gap-4 mb-6">
            <div className="col-span-1 bg-card border border-border rounded-xl p-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Total CVEs</p>
              <p className="text-3xl font-bold text-foreground">{stats.total}</p>
            </div>
            {Object.entries(AV_LABEL).map(([code, meta]) => (
              <div key={code} className={cn("bg-card border rounded-xl p-4 border-border cursor-pointer transition-all hover:border-primary/30", filterAV === code && "border-primary/60 bg-primary/5")}
                onClick={() => setFilterAV(filterAV === code ? "all" : code)}>
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">{meta.label}</p>
                <p className={cn("text-3xl font-bold", meta.color)}>{stats.avCount[meta.label] ?? 0}</p>
              </div>
            ))}
          </div>

          {/* Filters */}
          <div className="flex items-center gap-3 mb-5">
            <input
              type="text"
              placeholder="Search CVE ID or target…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="flex-1 max-w-xs px-3 py-2 text-sm bg-card border border-border rounded-lg focus:outline-none focus:border-primary/50"
            />
            <select value={filterAV} onChange={e => setFilterAV(e.target.value)}
              className="px-3 py-2 text-sm bg-card border border-border rounded-lg focus:outline-none focus:border-primary/50">
              <option value="all">All Vectors</option>
              {Object.entries(AV_LABEL).map(([code, meta]) => (
                <option key={code} value={code}>{meta.label}</option>
              ))}
            </select>
            <select value={filterSev} onChange={e => setFilterSev(e.target.value)}
              className="px-3 py-2 text-sm bg-card border border-border rounded-lg focus:outline-none focus:border-primary/50">
              <option value="all">All Severities</option>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            {(filterAV !== "all" || filterSev !== "all" || search) && (
              <button onClick={() => { setFilterAV("all"); setFilterSev("all"); setSearch(""); }}
                className="text-xs text-muted-foreground hover:text-foreground underline">
                Clear filters
              </button>
            )}
            <span className="ml-auto text-xs text-muted-foreground">{filtered.length} results</span>
          </div>

          {/* Table */}
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            {isLoading ? (
              <div className="flex items-center justify-center py-24 text-muted-foreground text-sm animate-pulse">
                Loading attack vector data…
              </div>
            ) : filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-24 gap-3 text-center">
                <Shield className="w-10 h-10 text-muted-foreground/30" />
                <p className="text-muted-foreground text-sm max-w-xs">
                  No data found. Run a scan and correlate with NVD to populate this table.
                </p>
              </div>
            ) : (
              <table className="w-full text-[12.5px]">
                <thead>
                  <tr className="border-b border-border bg-muted/20">
                    <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Target / Asset</th>
                    <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Vulnerability</th>
                    <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">CVSS Score</th>
                    <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Attack Vector</th>
                    <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Exploit Maturity</th>
                    <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Privileges Required</th>
                    <th className="text-left px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">User Interaction</th>
                    <th className="px-4 py-3 text-[10px] font-bold uppercase tracking-wider text-muted-foreground w-8"></th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((row) => {
                    const rowKey = `${row.target}::${row.cve_id}`;
                    const parsed = parseVector(row.cvss_v3_vector);
                    const avMeta = AV_LABEL[parsed?.av ?? ""];
                    const isExpanded = expandedRows.has(rowKey);
                    const hasExploit = !!row.exploit_edb_id;
                    const weaponized = isWeaponizedScript(row.exploit_file);
                    const prMeta = PR_META[parsed?.pr ?? ""];
                    const uiMeta = UI_META[parsed?.ui ?? ""];

                    return (
                      <Fragment key={rowKey}>
                        <tr
                          onClick={() => toggleRow(rowKey)}
                          className={cn(
                            "border-b border-border/50 cursor-pointer transition-colors",
                            isExpanded ? "bg-primary/5" : "hover:bg-muted/20"
                          )}
                        >
                          {/* Target */}
                          <td className="px-4 py-3.5">
                            <span className="font-mono text-primary text-[11.5px]">{row.target}</span>
                          </td>

                          {/* CVE */}
                          <td className="px-4 py-3.5">
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${row.cve_id}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={e => e.stopPropagation()}
                              className="font-mono text-primary hover:underline"
                            >
                              {row.cve_id}
                            </a>
                          </td>

                          {/* Score */}
                          <td className="px-4 py-3.5">
                            <ScoreBadge score={row.cvss_v3_score} severity={row.cvss_v3_severity} />
                          </td>

                          {/* AV */}
                          <td className="px-4 py-3.5">
                            {avMeta ? (
                              <span className={cn(
                                "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-semibold",
                                avMeta.bg, avMeta.color
                              )}>
                                <Wifi className="w-3 h-3" />
                                {avMeta.label}
                              </span>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </td>

                          {/* Exploit Maturity */}
                          <td className="px-4 py-3.5" onClick={e => e.stopPropagation()}>
                            {weaponized ? (
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-red-500/15 text-red-400 border border-red-500/30">
                                  🔥 Functional Weaponized Script
                                </span>
                                <a
                                  href={`https://www.exploit-db.com/exploits/${row.exploit_edb_id}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  title={`Download: ${row.exploit_file}`}
                                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-primary text-primary-foreground text-[11px] font-semibold hover:bg-primary/90 transition-colors"
                                >
                                  <Download className="w-3 h-3" />
                                  Download
                                </a>
                              </div>
                            ) : hasExploit ? (
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/30">
                                  ⚡ Confirmed Exploit (Non-Script)
                                </span>
                                <a
                                  href={`https://www.exploit-db.com/exploits/${row.exploit_edb_id}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  title={`Download: ${row.exploit_file}`}
                                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-primary text-primary-foreground text-[11px] font-semibold hover:bg-primary/90 transition-colors"
                                >
                                  <Download className="w-3 h-3" />
                                  Download
                                </a>
                              </div>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-[11px] font-bold">
                                <span className="text-green-400">Theoretical</span>
                                <span className="text-muted-foreground/60">/</span>
                                <span className="text-yellow-400">PoC Only</span>
                              </span>
                            )}
                          </td>

                          {/* Privileges Required */}
                          <td className="px-4 py-3.5">
                            {prMeta ? (
                              <span
                                title={prMeta.title}
                                className={cn(
                                  "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-semibold cursor-help",
                                  prMeta.bg, prMeta.color
                                )}
                              >
                                <Lock className="w-3 h-3" />
                                {prMeta.label}
                              </span>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </td>

                          {/* User Interaction */}
                          <td className="px-4 py-3.5">
                            {uiMeta ? (
                              <span
                                title={uiMeta.title}
                                className={cn(
                                  "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-semibold cursor-help",
                                  uiMeta.bg, uiMeta.color
                                )}
                              >
                                <User className="w-3 h-3" />
                                {uiMeta.label}
                              </span>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </td>

                          {/* Expand */}
                          <td className="px-4 py-3.5 text-muted-foreground">
                            {isExpanded
                              ? <ChevronUp className="w-3.5 h-3.5" />
                              : <ChevronDown className="w-3.5 h-3.5" />
                            }
                          </td>
                        </tr>

                        {/* Expanded CIA + details row */}
                        {isExpanded && (
                          <tr key={`${rowKey}-expanded`} className="bg-muted/10 border-b border-border/30">
                            <td colSpan={8} className="px-6 py-4">
                              <div className="grid grid-cols-2 gap-6">
                                {/* CIA Impact */}
                                <div>
                                  <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-2">
                                    Security Impact Details (CIA Triad)
                                  </p>
                                  <ExpandedCIA parsed={parsed} description={row.description} />
                                </div>

                                {/* Description + vector + exploit */}
                                <div className="space-y-3">
                                  {row.description && (
                                    <div>
                                      <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-1">Description</p>
                                      <p className="text-[11.5px] text-muted-foreground leading-relaxed line-clamp-5">{row.description}</p>
                                    </div>
                                  )}
                                  {row.cvss_v3_vector && (
                                    <div>
                                      <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-1">CVSS v3 Vector</p>
                                      <code className="text-[10.5px] text-primary font-mono bg-primary/5 px-2 py-1 rounded border border-primary/10 block break-all">
                                        {row.cvss_v3_vector}
                                      </code>
                                    </div>
                                  )}
                                  {hasExploit && row.exploit_file && (
                                    <div>
                                      <p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-1">Exploit File</p>
                                      <div className="flex items-center gap-2">
                                        <code className="text-[10.5px] text-orange-400 font-mono bg-orange-500/5 px-2 py-1 rounded border border-orange-500/15 flex-1 truncate">
                                          {row.exploit_file}
                                        </code>
                                        <a
                                          href={`https://www.exploit-db.com/exploits/${row.exploit_edb_id}`}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-[11px] font-semibold hover:bg-primary/90 transition-colors shrink-0"
                                        >
                                          <Download className="w-3 h-3" />
                                          Download Exploit
                                        </a>
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {!isLoading && filtered.length > 0 && (
            <p className="text-[10.5px] text-muted-foreground/50 mt-3 text-center">
              Click any row to expand CIA security impact details · CVE links open NVD · Hover badges for full description
            </p>
          )}
        </main>
      </div>
    </div>
  );
};

export default AttackVectorPage;
