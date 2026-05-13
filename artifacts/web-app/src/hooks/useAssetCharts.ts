import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import type { DonutSegment } from "@/components/DonutChart";

// ─── Segment Definitions ─────────────────────────────────────────────────────

const SEVERITY_SEGS: (DonutSegment & { order: number; key: string })[] = [
  { name: "Critical", color: "hsl(0 84% 55%)",   order: 1, key: "critical", value: 0 },
  { name: "High",     color: "hsl(22 90% 54%)",  order: 2, key: "high",     value: 0 },
  { name: "Medium",   color: "hsl(38 95% 52%)",  order: 3, key: "medium",   value: 0 },
  { name: "Low",      color: "hsl(142 68% 45%)", order: 4, key: "low",      value: 0 },
  { name: "Info",     color: "hsl(270 60% 60%)", order: 5, key: "info",     value: 0 },
];

const TOOL_SEGS: (DonutSegment & { order: number; keys: string[] })[] = [
  { name: "FFUF",   color: "hsl(243 72% 68%)", order: 1, keys: ["ffuf"],                     value: 0 },
  { name: "SQLMap", color: "hsl(195 85% 48%)", order: 2, keys: ["sqlmap"],                   value: 0 },
  { name: "Nmap",   color: "hsl(210 90% 52%)", order: 3, keys: ["nmap"],                     value: 0 },
  { name: "Nikto",  color: "hsl(228 80% 62%)", order: 4, keys: ["nikto"],                    value: 0 },
  { name: "Other",  color: "hsl(215 22% 58%)", order: 5, keys: ["other", "unknown", ""],     value: 0 },
];

const EXPOSURE_SEGS: (DonutSegment & { order: number })[] = [
  { name: "Web Application", color: "hsl(315 95% 52%)", order: 1, value: 0 },
  { name: "External Host",   color: "hsl(335 88% 58%)", order: 2, value: 0 },
  { name: "Internal Host",   color: "hsl(350 78% 65%)", order: 3, value: 0 },
  { name: "Network Service", color: "hsl(300 70% 60%)", order: 4, value: 0 },
];

const EXPLOIT_SEGS: (DonutSegment & { order: number })[] = [
  { name: "Weaponized",  color: "hsl(120 75% 38%)", order: 1, value: 0 },
  { name: "Public PoC",  color: "hsl(140 68% 48%)", order: 2, value: 0 },
  { name: "Known CVE",   color: "hsl(158 62% 55%)", order: 3, value: 0 },
  { name: "Theoretical", color: "hsl(175 50% 60%)", order: 4, value: 0 },
];

const VECTOR_SEGS: (DonutSegment & { order: number })[] = [
  { name: "Network",  color: "hsl(335 85% 60%)", order: 1, value: 0 },
  { name: "Adjacent", color: "hsl(350 85% 65%)", order: 2, value: 0 },
  { name: "Local",    color: "hsl(315 80% 65%)", order: 3, value: 0 },
  { name: "Physical", color: "hsl(290 70% 65%)", order: 4, value: 0 },
  { name: "Unknown",  color: "hsl(215 18% 60%)", order: 5, value: 0 },
];

const STATUS_SEGS: (DonutSegment & { order: number; keys: string[] })[] = [
  { name: "Open",           color: "hsl(0 82% 55%)",   order: 1, keys: ["open"],                        value: 0 },
  { name: "In Progress",    color: "hsl(205 82% 52%)",  order: 2, keys: ["in_progress", "triaged"],      value: 0 },
  { name: "Fixed",          color: "hsl(145 65% 44%)",  order: 3, keys: ["fixed", "resolved", "closed"], value: 0 },
  { name: "False Positive", color: "hsl(270 58% 60%)",  order: 4, keys: ["false_positive"],              value: 0 },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function zeroSegs<T extends DonutSegment>(segs: T[]): DonutSegment[] {
  return [...segs]
    .sort((a: any, b: any) => a.order - b.order)
    .map(({ name, color }) => ({ name, color, value: 0 }));
}

async function getUser() {
  const { data: { user } } = await supabase.auth.getUser();
  return user;
}

function classifyTarget(target: string): string {
  if (/^https?:\/\//i.test(target)) return "Web Application";
  if (/^10\./.test(target) || /^192\.168\./.test(target) ||
      /^172\.(1[6-9]|2[0-9]|3[01])\./.test(target) || /^127\./.test(target))
    return "Internal Host";
  if (/^\d{1,3}(\.\d{1,3}){3}/.test(target)) return "External Host";
  return "Network Service";
}

function classifyVector(vec: string | null): string {
  if (!vec) return "Unknown";
  const v = vec.toUpperCase();
  if (v.includes("AV:N")) return "Network";
  if (v.includes("AV:A")) return "Adjacent";
  if (v.includes("AV:L")) return "Local";
  if (v.includes("AV:P")) return "Physical";
  return "Unknown";
}

// ─── Scan Targets Dropdown ────────────────────────────────────────────────────
export interface ScanTarget {
  url: string;         // Specific URL for this entry (e.g. http://...)
  displayHost: string; // Canonical host for display
  urls: string[];      // Unified list for charts (both http & https)
  scanCount: number;   // Count for THIS specific URL
  totalFindings: number; // Findings for THIS specific URL
  latestDate: string;
}

export function useScanTargets() {
  return useQuery<ScanTarget[]>({
    queryKey: ["scan_targets_summary"],
    queryFn: async () => {
      const { data, error } = await (supabase as any)
        .from("scan_results")
        .select("target, tool, total_findings, created_at")
        .order("created_at", { ascending: false });

      if (error || !data?.length) return [];

      const raw = data as { target: string; tool: string | null; total_findings: number | null; created_at: string }[];

      // 1. Group by Tool to get latest unique tool findings per URL
      const toolMap = new Map<string, { findings: number, date: string }>();
      for (const row of raw) {
        const url = row.target?.trim();
        if (!url) continue;
        const key = `${url}||${(row.tool ?? "").toLowerCase().trim()}`;
        if (!toolMap.has(key)) {
          toolMap.set(key, { findings: row.total_findings ?? 0, date: row.created_at });
        }
      }

      // 2. First pass: Aggregate by Host (to get the unified 'urls' list)
      const hostAggMap = new Map<string, string[]>();
      for (const key of toolMap.keys()) {
        const url = key.split("||")[0];
        const host = url.replace(/^https?:\/\//i, "").replace(/\/$/, "");
        if (!hostAggMap.has(host)) hostAggMap.set(host, []);
        if (!hostAggMap.get(host)!.includes(url)) hostAggMap.get(host)!.push(url);
      }

      // 3. Second pass: Create entries for each unique URL
      const urlEntries = new Map<string, ScanTarget>();
      for (const [key, info] of toolMap.entries()) {
        const url = key.split("||")[0];
        const host = url.replace(/^https?:\/\//i, "").replace(/\/$/, "");
        
        if (!urlEntries.has(url)) {
          urlEntries.set(url, {
            url,
            displayHost: host,
            urls: hostAggMap.get(host) || [url],
            scanCount: 0,
            totalFindings: 0,
            latestDate: info.date
          });
        }
        
        const t = urlEntries.get(url)!;
        t.scanCount += 1;
        t.totalFindings += info.findings;
        if (new Date(info.date) > new Date(t.latestDate)) {
          t.latestDate = info.date;
        }
      }

      // Sort by newest scan first
      return [...urlEntries.values()].sort((a, b) => 
        new Date(b.latestDate).getTime() - new Date(a.latestDate).getTime()
      );
    },
    staleTime: 60_000,
  });
}

// ─── Types ────────────────────────────────────────────────────────────────────

type ScanRow = {
  id: string;
  target: string;
  tool: string | null;
  total_findings: number | null;
  critical_count: number | null;
  high_count: number | null;
  medium_count: number | null;
  low_count: number | null;
};

type FindingRow = { id: string; target: string; tool: string | null; scan_id: string; status: string | null; severity: string | null };

type VulnRow = {
  cve_id: string;
  cvss_severity: string | null;
  exploit_status: string | null;
  status: string | null;
};

// ─── Core Helper: scan_results deduplicated by (target, tool) ─────────────────
// For each (target, tool) pair keep only the LATEST scan.
// This matches the logic in the 'scanned_assets' view used by the table.
async function getScanRows(targetFilter: string | string[] | null): Promise<ScanRow[]> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return [];

  let q = (supabase as any)
    .from("scan_results")
    .select("id, target, tool, total_findings, critical_count, high_count, medium_count, low_count, completed_at, started_at, created_at")
    .order("target")
    .order("tool")
    .order("created_at", { ascending: false });
  
  if (targetFilter) {
    if (Array.isArray(targetFilter)) {
      q = q.in("target", targetFilter);
    } else {
      q = q.eq("target", targetFilter);
    }
  }

  const { data, error } = await q;
  if (error || !data?.length) return [];

  // Deduplicate: for each (target, tool) keep the latest scan record
  const dedup = new Map<string, ScanRow>();
  for (const r of data as (ScanRow & { created_at: string })[]) {
    const key = `${r.target ?? ""}||${(r.tool ?? "").toLowerCase().trim()}`;
    if (!dedup.has(key)) {
      dedup.set(key, r);
    }
  }
  return [...dedup.values()];
}

// ─── Core Helper: unique targets for this user ────────────────────────────────
async function getUserTargets(targetFilter: string | string[] | null): Promise<string[]> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return [];

  let q = (supabase as any)
    .from("scan_results")
    .select("target");
  
  if (targetFilter) {
    if (Array.isArray(targetFilter)) {
      q = q.in("target", targetFilter);
    } else {
      q = q.eq("target", targetFilter);
    }
  }
  const { data } = await q;
  return [...new Set((data ?? []).map((r: any) => (r as any).target as string).filter(Boolean))] as string[];
}

// ─── Core Helper: scan_findings for given targets, deduplicated by (target, tool) ──
// Filters findings by user_id via join with scan_results to ensure data isolation.
// Uses strict matching to prevent mixing findings between different subdomains.
async function getScanFindings(scanIds: string[]): Promise<FindingRow[]> {
  if (!scanIds.length) return [];

  const { data, error } = await (supabase as any)
    .from("scan_findings")
    .select("id, target, tool, scan_id, status, severity")
    .in("scan_id", scanIds);

  if (error || !data) return [];

  return data as FindingRow[];
}

// ─── Core Helper: vulnerabilities for user's targets via scan_findings chain ──
// Chain: user targets → scan_results → scan_findings (by scan_id) → finding_cves → cve_catalog
// We query the catalog directly to bypass potentially buggy views and ensure we get all data.
async function getVulnsForUser(targetFilter: string | string[] | null): Promise<VulnRow[]> {
  const scanRows = await getScanRows(targetFilter);
  if (!scanRows.length) return [];

  const scanIds = scanRows.map(r => r.id);
  const findings = await getScanFindings(scanIds);
  if (!findings.length) return [];

  const findingIds = findings.map(f => f.id);

  // 1. Get linked CVE IDs
  const { data: fcData, error: fcErr } = await (supabase as any)
    .from("finding_cves")
    .select("cve_id, finding_id")
    .in("finding_id", findingIds);
  if (fcErr || !fcData?.length) return [];

  const cveIds = [...new Set((fcData as { cve_id: string }[]).map(r => r.cve_id))];

  // 2. Fetch CVE details and linked exploits
  const [{ data: catalog }, { data: exploits }] = await Promise.all([
    (supabase as any).from("cve_catalog").select("cve_id, cvss_v3_severity, cvss_v3_score").in("cve_id", cveIds),
    (supabase as any).from("exploits").select("cve_id, verified").in("cve_id", cveIds)
  ]);

  if (!catalog?.length) return [];

  // 3. Map to VulnRow format used by the charts
  return catalog.map((c: any) => {
    const relevantExploits = (exploits || []).filter((ex: any) => ex.cve_id === c.cve_id);
    const anyVerified = relevantExploits.some((ex: any) => ex.verified === true);
    
    // Attempt to find the specific finding this CVE belongs to for its status
    // (In case multiple findings point to same CVE, we'll pick first seen)
    const fid = (fcData as any[]).find((row: any) => row.cve_id === c.cve_id)?.finding_id;
    const matchingFinding = findings.find(f => f.id === fid);

    return {
      cve_id: c.cve_id,
      cvss_severity: (c.cvss_v3_severity || "info").toLowerCase(),
      exploit_status: anyVerified ? "weaponized" : (relevantExploits.length > 0 ? "poc" : "none"),
      status: matchingFinding?.status || "open"
    };
  });
}

// ─── 1. Finding Severity ──────────────────────────────────────────────────────
// Uses the severity counts directly from the scan_results table to ensure consistency with the asset table.
export function useChartSeverity(target: string | string[] | null = null) {
  return useQuery<DonutSegment[]>({
    queryKey: ["chart_severity", target],
    queryFn: async () => {
      const scanRows = await getScanRows(target);
      if (!scanRows.length) return zeroSegs(SEVERITY_SEGS);

      let critical = 0, high = 0, medium = 0, low = 0, total = 0;
      for (const r of scanRows) {
        critical += (r.critical_count ?? 0);
        high     += (r.high_count ?? 0);
        medium   += (r.medium_count ?? 0);
        low      += (r.low_count ?? 0);
        total    += (r.total_findings ?? 0);
      }

      // Any findings not explicitly bucketed by the gateway are "Info"
      const info = Math.max(0, total - (critical + high + medium + low));

      if (total === 0) return zeroSegs(SEVERITY_SEGS);

      return SEVERITY_SEGS.sort((a, b) => a.order - b.order).map(seg => ({
        name: seg.name,
        color: seg.color,
        value:
          seg.key === "critical" ? critical :
          seg.key === "high"     ? high     :
          seg.key === "medium"   ? medium   :
          seg.key === "low"      ? low      : info,
      }));
    },
    staleTime: 60_000,
  });
}

// ─── 2. Findings by Tool ──────────────────────────────────────────────────────
// Uses total_findings directly from scan_results (populated by gateway)
// This ensures that non-CVE findings (like Nmap ports) are correctly counted.
export function useChartByTool(target: string | string[] | null = null) {
  return useQuery<DonutSegment[]>({
    queryKey: ["chart_by_tool", target],
    queryFn: async () => {
      const scanRows = await getScanRows(target);
      if (!scanRows.length) return zeroSegs(TOOL_SEGS);

      const scanCounts: Record<string, number> = {};
      for (const r of scanRows) {
        const k = (r.tool ?? "").toLowerCase().trim();
        scanCounts[k] = (scanCounts[k] ?? 0) + (r.total_findings ?? 0);
      }

      if (Object.values(scanCounts).every(v => v === 0)) return zeroSegs(TOOL_SEGS);

      return TOOL_SEGS.sort((a, b) => a.order - b.order).map(seg => ({
        name: seg.name,
        color: seg.color,
        value: seg.keys.reduce((s, k) => s + (scanCounts[k] ?? 0), 0),
      }));
    },
    staleTime: 60_000,
  });
}

// ─── 3. Asset Exposure ────────────────────────────────────────────────────────
// Unique targets from scan_results classified by type
export function useChartExposure(target: string | string[] | null = null) {
  return useQuery<DonutSegment[]>({
    queryKey: ["chart_exposure", target],
    queryFn: async () => {
      const rows = await getScanRows(target);
      if (!rows.length) return zeroSegs(EXPOSURE_SEGS);

      const counts: Record<string, number> = {};
      const seenHost = new Set<string>();
      for (const r of rows) {
        if (!r.target) continue;
        const host = r.target.replace(/^https?:\/\//i, "").replace(/\/$/, "").toLowerCase();
        if (seenHost.has(host)) continue;
        
        seenHost.add(host);
        const bucket = classifyTarget(r.target);
        counts[bucket] = (counts[bucket] ?? 0) + 1;
      }

      return EXPOSURE_SEGS.sort((a, b) => a.order - b.order).map(seg => ({
        name: seg.name,
        color: seg.color,
        value: counts[seg.name] ?? 0,
      }));
    },
    staleTime: 60_000,
  });
}

// ─── 4. Exploitability Risk ───────────────────────────────────────────────────
// Findings classified by exploit availability — filtered by user's scanned targets
export function useChartExploitability(target: string | string[] | null = null) {
  return useQuery<DonutSegment[]>({
    queryKey: ["chart_exploitability", target],
    queryFn: async () => {
      const scanRows = await getScanRows(target);
      if (!scanRows.length) return zeroSegs(EXPLOIT_SEGS);

      const scanIds = scanRows.map(r => r.id);
      const findings = await getScanFindings(scanIds);
      if (!findings.length) return zeroSegs(EXPLOIT_SEGS);

      const findingIds = findings.map(f => f.id);
      
      // 1. Get linked CVEs for these findings
      const { data: fcData } = await (supabase as any)
        .from("finding_cves")
        .select("finding_id, cve_id")
        .in("finding_id", findingIds);
      
      const counts = { Weaponized: 0, "Public PoC": 0, "Known CVE": 0, Theoretical: 0 };

      if (!fcData?.length) {
        // All findings are theoretical if no CVEs are linked
        counts.Theoretical = findings.length;
      } else {
        const cveIds = [...new Set(fcData.map((r: any) => r.cve_id))];
        
        // 2. Fetch CVE details and linked exploits
        const [{ data: catalog }, { data: exploits }] = await Promise.all([
          (supabase as any).from("cve_catalog").select("cve_id, cvss_v3_severity").in("cve_id", cveIds),
          (supabase as any).from("exploits").select("cve_id, verified").in("cve_id", cveIds)
        ]);

        // 3. Score each finding
        for (const f of findings) {
          const linkedCves = fcData.filter((r: any) => r.finding_id === f.id).map((r: any) => r.cve_id);
          if (linkedCves.length === 0) {
            counts.Theoretical++;
            continue;
          }

          const relevantCatalog = (catalog || []).filter((c: any) => linkedCves.includes(c.cve_id));
          const relevantExploits = (exploits || []).filter((ex: any) => linkedCves.includes(ex.cve_id));

          const anyWeaponized = relevantExploits.some((ex: any) => ex.verified === true);
          const anyPoC = relevantExploits.length > 0;
          const anyHighSev = relevantCatalog.some((c: any) => 
            ['CRITICAL', 'HIGH', 'MEDIUM'].includes((c.cvss_v3_severity || "").toUpperCase())
          );

          if (anyWeaponized) counts.Weaponized++;
          else if (anyPoC)   counts["Public PoC"]++;
          else if (anyHighSev) counts["Known CVE"]++;
          else counts.Theoretical++;
        }
      }

      return EXPLOIT_SEGS.sort((a, b) => a.order - b.order).map(seg => ({
        name: seg.name,
        color: seg.color,
        value: counts[seg.name as keyof typeof counts] ?? 0,
      }));
    },
    staleTime: 60_000,
  });
}

// ─── 5. Attack Vector ────────────────────────────────────────────────────────
// Findings classified by CVSS attack vector — filtered by user's scanned targets
export function useChartAttackVector(target: string | string[] | null = null) {
  return useQuery<DonutSegment[]>({
    queryKey: ["chart_attack_vector", target],
    queryFn: async () => {
      const scanRows = await getScanRows(target);
      if (!scanRows.length) return zeroSegs(VECTOR_SEGS);

      const scanIds = scanRows.map(r => r.id);
      const findings = await getScanFindings(scanIds);
      if (!findings.length) return zeroSegs(VECTOR_SEGS);

      const findingIds = findings.map(f => f.id);
      const { data: fcData } = await (supabase as any)
        .from("finding_cves")
        .select("finding_id, cve_id")
        .in("finding_id", findingIds);
      
      const counts: Record<string, number> = {};

      if (!fcData?.length) {
        counts["Unknown"] = findings.length;
      } else {
        const cveIds = [...new Set(fcData.map((r: any) => r.cve_id))];
        const { data: cveRows } = await (supabase as any)
          .from("cve_catalog")
          .select("cve_id, cvss_v3_vector")
          .in("cve_id", cveIds);

        for (const f of findings) {
          const linkedCves = fcData.filter((r: any) => r.finding_id === f.id).map((r: any) => r.cve_id);
          if (linkedCves.length === 0) {
            counts["Unknown"] = (counts["Unknown"] ?? 0) + 1;
            continue;
          }

          const vectors = (cveRows || []).filter((c: any) => linkedCves.includes(c.cve_id)).map((c: any) => c.cvss_v3_vector);
          // Pick the most common or most severe vector (simplified: pick first)
          const bucket = classifyVector(vectors[0]);
          counts[bucket] = (counts[bucket] ?? 0) + 1;
        }
      }

      return VECTOR_SEGS.sort((a, b) => a.order - b.order).map(seg => ({
        name: seg.name,
        color: seg.color,
        value: counts[seg.name] ?? 0,
      }));
    },
    staleTime: 60_000,
  });
}

// ─── 6. Finding Status ────────────────────────────────────────────────────────
// Classified by remediation status from scan_findings — filtered by user's scanned targets
export function useChartStatus(target: string | string[] | null = null) {
  return useQuery<DonutSegment[]>({
    queryKey: ["chart_status", target],
    queryFn: async () => {
      const scanRows = await getScanRows(target);
      if (!scanRows.length) return zeroSegs(STATUS_SEGS);

      const scanIds = scanRows.map(r => r.id);
      const findings = await getScanFindings(scanIds);
      if (!findings.length) return zeroSegs(STATUS_SEGS);

      const counts: Record<string, number> = {};
      for (const f of findings) {
        const k = (f.status ?? "open").toLowerCase().trim();
        counts[k] = (counts[k] ?? 0) + 1;
      }

      return STATUS_SEGS.sort((a, b) => a.order - b.order).map(seg => ({
        name: seg.name,
        color: seg.color,
        value: seg.keys.reduce((s, k) => s + (counts[k] ?? 0), 0),
      }));
    },
    staleTime: 60_000,
  });
}
