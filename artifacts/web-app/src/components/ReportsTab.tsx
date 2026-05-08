import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "@/contexts/AuthContext";
import { FileText, Download, Calendar, Circle, Target, ChevronDown } from "lucide-react";
import { toast } from "sonner";

const ReportsTab = () => {
  const [selectedFormat, setSelectedFormat] = useState<string | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string>("all");
  const { userRole } = useAuth();

  const { data: scans = [] } = useQuery({
    queryKey: ["report_scans", userRole],
    queryFn: async () => {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return [];

      let query = supabase
        .from("scan_results" as any)
        .select("id, name, target, created_at, status, tool, critical_count, high_count, medium_count, low_count, total_findings")
        .eq("status", "completed")
        .order("created_at", { ascending: false });

      if (userRole !== 'admin') {
        query = (query as any).eq("user_id", user.id);
      }

      const { data, error } = await query;
      if (error) throw error;
      return data as any[];
    },
  });

  const { data: reportData = [] } = useQuery({
    queryKey: ["target_report_data", selectedScanId, userRole],
    queryFn: async () => {
      if (selectedScanId === "all") return [];
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return [];

      let query = supabase
        .from("target_report_data" as any)
        .select("*")
        .eq("scan_id", selectedScanId);

      if (userRole !== 'admin') {
        query = (query as any).eq("user_id", user.id);
      }

      const { data, error } = await query;
      if (error) throw error;
      return data as any[];
    },
    enabled: selectedScanId !== "all"
  });

  const { data: globalVulnerabilities = [] } = useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: async () => {
      const { data, error } = await supabase.from("vulnerabilities").select("*");
      if (error) throw error;
      return data;
    },
  });

  const { data: globalSummary = [] } = useQuery({
    queryKey: ["vulnerability_summary"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("vulnerability_summary")
        .select("*")
        .order("sort_order", { ascending: true });
      if (error) throw error;
      return data;
    },
  });

  const selectedScan = scans.find(s => s.id === selectedScanId);

  // Calculate filtered summary stats using the source of truth (scan_results table)
  const severityCounts = {
    Critical: selectedScan?.critical_count ?? 0,
    High: selectedScan?.high_count ?? 0,
    Medium: selectedScan?.medium_count ?? 0,
    Low: selectedScan?.low_count ?? 0,
    Total: selectedScan?.total_findings ?? 0,
  };

  const filteredSummary = [
    { label: "Total Findings", value: severityCounts.Total, id: "total", sort_order: 1 },
    { label: "Critical", value: severityCounts.Critical, id: "crit", sort_order: 2 },
    { label: "High", value: severityCounts.High, id: "high", sort_order: 3 },
    { label: "Medium", value: severityCounts.Medium, id: "med", sort_order: 4 },
    { label: "Low", value: severityCounts.Low, id: "low", sort_order: 5 },
  ];

  const displayCriticalCount = selectedScanId === "all" 
    ? globalVulnerabilities.filter((v) => v.exprt_rating === "Critical").length
    : severityCounts.Critical;

  const displayTotalFindings = selectedScanId === "all"
    ? globalVulnerabilities.length
    : severityCounts.Total;

  // Top 5 vulnerabilities
  const top5 = selectedScanId === "all" 
    ? globalVulnerabilities
        .sort((a, b) => (b.vulnerability_count || 0) - (a.vulnerability_count || 0))
        .slice(0, 5)
        .map(v => ({ id: v.id, label: v.cve_id, sublabel: `${v.vulnerability_count} assets` }))
    : [...reportData]
        .sort((a, b) => (b.severity_score || 0) - (a.severity_score || 0))
        .slice(0, 5)
        .map(v => ({ id: v.finding_id, label: v.vulnerability_name, sublabel: v.severity_score === 4 ? 'Critical' : v.severity_score === 3 ? 'High' : 'Info' }));

  const handleDownload = async (format: string) => {
    if (selectedScanId === "all") {
      toast.error("Please select a scan to generate a report");
      return;
    }

    const selectedScan = scans.find(s => s.id === selectedScanId);
    if (!selectedScan) {
      toast.error("Scan data not found");
      return;
    }

    const targetInfo = {
      target: selectedScan.target,
      scan_name: selectedScan.name,
      tool: selectedScan.tool,
      created_at: selectedScan.created_at
    };

    const dateStr = new Date().toLocaleDateString("en-US", { 
      year: 'numeric', month: 'long', day: 'numeric' 
    });

    if (format === "PDF") {
      // -----------------------------------------------------------
      // DATA CONSOLIDATION & NOISE REDUCTION LOGIC
      // -----------------------------------------------------------
      const consolidatedFindings: Record<string, any> = {};

      reportData.forEach((f) => {
        // Group by Service Info (e.g., Apache/2.4.7) or Vulnerability Name
        const groupKey = f.service_info || f.vulnerability_name || "General Discovery";

        if (!consolidatedFindings[groupKey]) {
          consolidatedFindings[groupKey] = {
            name: groupKey,
            path: f.finding_path,
            evidence: new Set([f.finding_evidence].filter(Boolean)),
            status: f.finding_status,
            severity_score: f.severity_score,
            cves: {}, // Map by CVE ID to dedup
          };
        }

        // Merge CVEs
        if (f.cve_details) {
          f.cve_details.forEach((cve: any) => {
            if (!consolidatedFindings[groupKey].cves[cve.cve_id]) {
              consolidatedFindings[groupKey].cves[cve.cve_id] = cve;
            }
          });
        }

        // Update severity to the highest found in group
        if (f.severity_score > consolidatedFindings[groupKey].severity_score) {
          consolidatedFindings[groupKey].severity_score = f.severity_score;
        }
      });

      const finalFindings = Object.values(consolidatedFindings).map(group => {
        const cveList = Object.values(group.cves) as any[];

        // Categorize CVEs: Modern/High vs Legacy/Low
        const highPriority = cveList.filter(c => {
          const yearMatch = c.cve_id.match(/CVE-(\d{4})-/);
          const year = yearMatch ? parseInt(yearMatch[1]) : 0;
          return (c.cvss_v3_score >= 7.0) || (year >= 2018);
        });

        const legacyMinor = cveList.filter(c => {
          const yearMatch = c.cve_id.match(/CVE-(\d{4})-/);
          const year = yearMatch ? parseInt(yearMatch[1]) : 0;
          return (c.cvss_v3_score < 5.0) || (year < 2015);
        });

        const midPriority = cveList.filter(c => !highPriority.includes(c) && !legacyMinor.includes(c));

        return {
          ...group,
          evidence: Array.from(group.evidence as Set<string>),
          highPriority: [...highPriority, ...midPriority].sort((a,b) => (b.cvss_v3_score || 0) - (a.cvss_v3_score || 0)),
          legacyMinor: legacyMinor.sort((a,b) => (b.cvss_v3_score || 0) - (a.cvss_v3_score || 0)),
        };
      });

      const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report - ${targetInfo.scan_name}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
        
        :root {
            --primary: #0ea5e9;
            --primary-dark: #0369a1;
            --bg-dark: #0f172a;
            --text-main: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #d97706;
            --low: #16a34a;
            --info: #2563eb;
        }
        
        body { 
            font-family: 'Plus Jakarta Sans', sans-serif; 
            background: #fff; 
            color: var(--text-main); 
            line-height: 1.3;
            padding: 0; 
            margin: 0; 
            font-size: 11px;
            -webkit-print-color-adjust: exact;
        }
        
        .page { 
            padding: 25px 35px;
            max-width: 1000px; 
            margin: 0 auto; 
            background: white; 
            position: relative;
        }

        .header-main { 
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
        }

        .header-main .logo {
            font-size: 16px;
            font-weight: 800;
            color: var(--primary);
        }
        
        .cover { 
            height: 100vh; 
            display: flex; 
            flex-direction: column; 
            justify-content: center; 
            align-items: center; 
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); 
            color: white; 
            text-align: center;
        }
        
        .cover h1 { font-size: 42px; font-weight: 800; margin-bottom: 15px; letter-spacing: -0.02em; }
        
        .summary-card { 
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 25px;
        }
        
        .section-title {
            font-size: 20px;
            font-weight: 800;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--bg-dark);
        }

        .section-title::before {
            content: "";
            width: 4px;
            height: 20px;
            background: var(--primary);
            border-radius: 2px;
        }

        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(5, 1fr); 
            gap: 8px;
        }
        
        .stat-card { 
            padding: 12px 5px;
            border-radius: 6px;
            text-align: center; 
            border: 1px solid var(--border);
            background: white;
        }
        
        .stat-card .count { font-size: 20px; font-weight: 800; display: block; }
        .stat-card .label { font-size: 8px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; }

        .finding-group {
            border: 1px solid var(--border); 
            border-radius: 10px;
            margin-bottom: 25px;
            page-break-inside: avoid; 
        }
        
        .finding-header { 
            background: #f1f5f9;
            padding: 12px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }

        .severity-badge {
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 9px;
            font-weight: 800;
            color: white;
            text-transform: uppercase;
        }

        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 10.5px; table-layout: fixed; }
        th { text-align: left; background: #f8fafc; padding: 8px; border-bottom: 2px solid var(--border); font-weight: 700; color: var(--text-muted); text-transform: uppercase; font-size: 9px; }
        td { padding: 8px; border-bottom: 1px solid var(--border); vertical-align: top; word-wrap: break-word; }

        .cve-id { font-weight: 700; color: var(--primary); }
        .cvss-score { font-weight: 800; padding: 2px 5px; border-radius: 3px; display: inline-block; font-size: 10px; }

        .legacy-section { margin-top: 15px; padding-top: 12px; border-top: 1px dashed var(--border); }
        .legacy-title { font-size: 11px; font-weight: 700; color: var(--text-muted); margin-bottom: 8px; }

        .code-block {
            background: #0f172a;
            color: #38bdf8;
            padding: 12px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 9.5px;
            margin-top: 12px;
            white-space: pre-wrap;
            border: 1px solid #1e293b;
        }

        @media print {
            .page { padding: 0; width: 100%; }
            .finding-group { margin-bottom: 20px; }
            h1 { page-break-before: avoid; }
        }
    </style>
</head>
<body>
    <div class="cover">
        <h1>Vulnerability Report</h1>
        <p style="font-size: 18px; color: #94a3b8;">Analysis of ${targetInfo.target}</p>
        <p style="margin-top: 40px;">${dateStr}</p>
    </div>

    <div class="page">
        <div class="header-main">
            <div class="logo">PENTEST-PRO</div>
            <div style="font-size: 11px; color: var(--text-muted);">${targetInfo.target}</div>
        </div>

        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-card">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">
                <div>
                    <p style="margin: 0;">Assessment Target: <strong>${targetInfo.target}</strong></p>
                    <p style="margin: 5px 0 0 0; color: var(--text-muted);">Methodology: Automated Hybrid Intelligence (${targetInfo.tool})</p>
                </div>
                <div style="text-align: right;">
                    <p style="margin: 0; font-weight: 700;">Risk Score: ${
                        severityCounts.Critical > 0 ? 'CRITICAL' :
                        severityCounts.High > 0 ? 'HIGH' :
                        severityCounts.Medium > 0 ? 'MEDIUM' : 'LOW'
                    }</p>
                </div>
            </div>

            <div style="height: 8px; background: #e2e8f0; border-radius: 4px; display: flex; overflow: hidden; margin: 15px 0;">
                <div style="width: ${(severityCounts.Critical/severityCounts.Total)*100}%; background: var(--critical)"></div>
                <div style="width: ${(severityCounts.High/severityCounts.Total)*100}%; background: var(--high)"></div>
                <div style="width: ${(severityCounts.Medium/severityCounts.Total)*100}%; background: var(--medium)"></div>
                <div style="width: ${(severityCounts.Low/severityCounts.Total)*100}%; background: var(--low)"></div>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <span class="count">${severityCounts.Total}</span>
                    <span class="label">Total</span>
                </div>
                <div class="stat-card">
                    <span class="count" style="color: var(--critical)">${severityCounts.Critical}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="stat-card">
                    <span class="count" style="color: var(--high)">${severityCounts.High}</span>
                    <span class="label">High</span>
                </div>
                <div class="stat-card">
                    <span class="count" style="color: var(--medium)">${severityCounts.Medium}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="stat-card">
                    <span class="count" style="color: var(--low)">${severityCounts.Low}</span>
                    <span class="label">Low/Info</span>
                </div>
            </div>
        </div>

        <h2 class="section-title">Consolidated Findings</h2>

        ${finalFindings.length === 0 ? `
            <div style="text-align: center; padding: 40px; color: var(--text-muted); border: 1px dashed var(--border); border-radius: 10px;">
                No security vulnerabilities or exposures were detected during this scan.
            </div>
        ` : finalFindings.map((group, idx) => {
          const escapeHtml = (unsafe: string) => {
            if (!unsafe || typeof unsafe !== 'string') return '';
            return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
          };

          const sevLabels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
          const sev = sevLabels[group.severity_score] || 'INFO';

          return `
            <div class="finding-group">
                <div class="finding-header">
                    <span style="font-weight: 800; color: var(--bg-dark);">${idx + 1}. ${escapeHtml(group.name)}</span>
                    <span class="severity-badge" style="background: ${
                        sev === 'CRITICAL' ? 'var(--critical)' :
                        sev === 'HIGH' ? 'var(--high)' :
                        sev === 'MEDIUM' ? 'var(--medium)' :
                        sev === 'LOW' ? 'var(--low)' : 'var(--info)'
                    }">${sev}</span>
                </div>
                <div style="padding: 15px;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 12px; font-size: 10px;">
                        <div>
                            <span style="color: var(--text-muted); font-weight: 700; text-transform: uppercase; font-size: 8px;">Target Resource</span>
                            <div style="margin-top: 2px;">${escapeHtml(group.path || 'Host-level Service')}</div>
                        </div>
                        <div>
                            <span style="color: var(--text-muted); font-weight: 700; text-transform: uppercase; font-size: 8px;">Analysis Status</span>
                            <div style="margin-top: 2px; color: #16a34a; font-weight: 700;">● ${group.status.toUpperCase()}</div>
                        </div>
                    </div>

                    ${group.highPriority.length > 0 ? `
                        <div style="font-weight: 700; color: var(--bg-dark); margin-bottom: 8px; font-size: 11px;">Primary Vulnerabilities (NVD Verified)</div>
                        <table style="margin-bottom: 15px;">
                            <thead>
                                <tr>
                                    <th width="110">Identifier</th>
                                    <th width="70">CVSS v3</th>
                                    <th>Impact Analysis</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${group.highPriority.map((c: any) => `
                                    <tr>
                                        <td class="cve-id">${c.cve_id}</td>
                                        <td>
                                            <span class="cvss-score" style="background: ${
                                                c.cvss_v3_score >= 9 ? '#fee2e2; color: #dc2626' :
                                                c.cvss_v3_score >= 7 ? '#ffedd5; color: #ea580c' : '#fef9c3; color: #ca8a04'
                                            }">${c.cvss_v3_score || 'N/A'}</span>
                                        </td>
                                        <td style="line-height: 1.4;">${escapeHtml(c.description)}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    ` : ''}

                    ${group.legacyMinor.length > 0 ? `
                        <div class="legacy-section">
                            <div class="legacy-title">Supporting Evidence & Legacy CVEs (Consolidated Summary)</div>
                            <table>
                                <thead>
                                    <tr>
                                        <th width="90">CVE ID</th>
                                        <th width="50">Score</th>
                                        <th>Summary of Potential Exposure</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${group.legacyMinor.slice(0, 15).map((c: any) => `
                                        <tr>
                                            <td style="font-weight: 600; color: var(--text-muted);">${c.cve_id}</td>
                                            <td style="color: var(--text-muted);">${c.cvss_v3_score || 'N/A'}</td>
                                            <td style="color: var(--text-muted); font-style: italic;">${escapeHtml(c.description.substring(0, 140))}...</td>
                                        </tr>
                                    `).join('')}
                                    ${group.legacyMinor.length > 15 ? `
                                        <tr>
                                            <td colspan="3" style="text-align: center; color: var(--text-muted); font-size: 9px; padding: 5px;">
                                                ... and ${group.legacyMinor.length - 15} additional legacy vulnerabilities consolidated to save space.
                                            </td>
                                        </tr>
                                    ` : ''}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}

                    ${group.evidence.length > 0 ? `
                        <div class="code-block">
                            <div style="font-weight: 800; color: #fff; margin-bottom: 5px; text-transform: uppercase; font-size: 8px; border-bottom: 1px solid #1e293b; padding-bottom: 3px;">Technical Evidence / Tool Output</div>
                            ${escapeHtml(group.evidence.join('\n\n'))}
                        </div>
                    ` : ''}
                </div>
            </div>
          `;
        }).join('')}

        <div style="text-align: center; font-size: 10px; color: var(--text-muted); margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border);">
            Generated by Pentest-Pro Security Platform &copy; ${new Date().getFullYear()}
        </div>
    </div>

    <script>
        window.onload = () => { 
            setTimeout(() => { 
                window.print(); 
                window.onafterprint = () => window.close();
            }, 500);
        }
    </script>
</body>
</html>`;

      const reportWindow = window.open('', '_blank');
      if (reportWindow) {
        reportWindow.document.write(html);
        reportWindow.document.close();
        toast.success("Generating report... If the print dialog doesn't appear, check for popup blockers.");
      } else {
        toast.error("Could not open report window. Please allow popups for this site.");
      }
    }
  };

  const summaryColors: Record<string, string> = {
    "Total Vulnerabilities": "text-primary",
    Open: "text-primary",
    "In Progress": "text-primary",
    Closed: "text-primary",
    "Actively Exploited": "text-primary",
    "Unique CVE IDs": "text-primary",
  };

  return (
    <div className="space-y-4">
      <div className="bg-card rounded-lg border border-border p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-4 flex-1">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-primary" />
              <h3 className="text-sm font-semibold text-foreground whitespace-nowrap">Reports</h3>
            </div>
            
            <div className="relative flex-1 max-w-md">
              <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                <Target className="h-4 w-4 text-muted-foreground" />
              </div>
              <select
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
                className="w-full pl-10 pr-10 py-1.5 bg-background border border-border rounded-md text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary appearance-none cursor-pointer"
              >
                <option value="all">Select Scan Result...</option>
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({s.target}) - {new Date(s.created_at).toLocaleDateString("en-US")}
                  </option>
                ))}
              </select>
              <div className="absolute inset-y-0 right-3 flex items-center pointer-events-none">
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 ml-4">
            <button
              onClick={() => {
                setSelectedFormat("PDF");
                handleDownload("PDF");
              }}
              className={`flex items-center gap-1.5 px-4 py-2 rounded-md border text-sm font-bold transition-colors border-primary text-primary bg-primary/10 hover:bg-primary/20`}
            >
              <Download className="w-4 h-4" />
              Export PDF Report
            </button>
          </div>
        </div>

        <div className="bg-secondary/50 rounded-lg p-4">
          <p className="text-sm text-muted-foreground">
            {selectedScanId === "all" ? (
              <>
                Global executive summary:{" "}
                <strong className="text-foreground">{displayCriticalCount} critical vulnerabilities</strong>,{" "}
                <strong className="text-foreground">{globalVulnerabilities.length} vulnerability IDs</strong>.
              </>
            ) : (
              <>
                Scan summary:{" "}
                <strong className="text-foreground">{displayCriticalCount} critical vulnerabilities</strong>,{" "}
        <strong className="text-foreground">{displayTotalFindings} total findings</strong>. Full report available via export.
              </>
            )}
          </p>
          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Calendar className="w-3 h-3" />
              {new Date().toLocaleDateString("en-US", { month: 'long', year: 'numeric' })}
            </span>
            <span className="flex items-center gap-1">
              <Circle className="w-3 h-3" />
              {scans.length} scans available
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-card rounded-lg border border-border p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">Top 5 vulnerabilities</h3>
          <div className="space-y-4">
            {top5.map((v, i) => (
              <div key={v.id} className="flex items-center gap-3">
                <span className="text-primary font-bold text-sm">{i + 1}.</span>
                <span className="text-primary font-mono text-xs truncate max-w-[200px]" title={v.label}>{v.label}</span>
                <span className="text-muted-foreground text-xs">({v.sublabel})</span>
              </div>
            ))}
            {top5.length === 0 && <p className="text-xs text-muted-foreground">No findings yet.</p>}
          </div>
        </div>

        <div className="bg-card rounded-lg border border-border p-5">
          <h3 className="text-sm font-semibold text-foreground mb-4">
            {selectedScanId === "all" ? "Global Summary" : `Summary for Scan Result`}
          </h3>
          <div className="space-y-3">
            {(selectedScanId === "all" ? globalSummary : filteredSummary).map((s) => (
              <div key={s.id} className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{s.label}</span>
                <span className={`text-sm font-bold ${summaryColors[s.label] || "text-foreground"}`}>
                  {s.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportsTab;
