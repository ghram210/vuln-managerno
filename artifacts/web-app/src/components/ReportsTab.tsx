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
        .select("id, name, target, created_at, status, tool")
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

  // Calculate filtered summary stats
  const severityCounts = {
    Critical: reportData.filter(v => v.severity_score === 4).length,
    High: reportData.filter(v => v.severity_score === 3).length,
    Medium: reportData.filter(v => v.severity_score === 2).length,
    Low: reportData.filter(v => v.severity_score === 1).length,
  };

  const filteredSummary = [
    { label: "Total Findings", value: reportData.length, id: "total", sort_order: 1 },
    { label: "Critical", value: severityCounts.Critical, id: "crit", sort_order: 2 },
    { label: "High", value: severityCounts.High, id: "high", sort_order: 3 },
    { label: "Medium", value: severityCounts.Medium, id: "med", sort_order: 4 },
    { label: "Low", value: severityCounts.Low, id: "low", sort_order: 5 },
  ];

  const displayCriticalCount = selectedScanId === "all"
    ? globalVulnerabilities.filter((v) => v.exprt_rating === "Critical").length
    : severityCounts.Critical;

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
      const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report - ${targetInfo.scan_name}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');

        :root {
            --primary: #06b6d4;
            --background: #0f172a;
            --card: #1e293b;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: #334155;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #10b981;
        }

        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: #fff;
            color: #1e293b;
            line-height: 1.6;
            padding: 0;
            margin: 0;
            -webkit-print-color-adjust: exact;
        }

        .page {
            padding: 50px 60px;
            max-width: 900px;
            margin: 0 auto;
            background: white;
        }

        .header {
            border-bottom: 3px solid var(--primary);
            padding-bottom: 25px;
            margin-bottom: 40px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }

        .header h1 {
            color: var(--primary);
            margin: 0;
            font-size: 28px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: -0.025em;
        }

        .cover {
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            background: var(--background);
            color: white;
            position: relative;
            overflow: hidden;
        }

        .cover::before {
            content: "";
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: radial-gradient(circle at 50% 50%, rgba(6, 182, 212, 0.15) 0%, transparent 70%);
        }

        .cover h1 {
            font-size: 56px;
            font-weight: 800;
            color: var(--primary);
            margin-bottom: 10px;
            z-index: 1;
            letter-spacing: -0.05em;
        }

        .cover h2 {
            font-size: 26px;
            font-weight: 400;
            color: var(--muted);
            margin-bottom: 60px;
            z-index: 1;
        }

        .cover-meta {
            z-index: 1;
            background: rgba(255, 255, 255, 0.05);
            padding: 30px 60px;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .summary-box {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 40px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-top: 25px;
        }

        .stat-card {
            padding: 20px 15px;
            border-radius: 10px;
            text-align: center;
            color: white;
            font-weight: 800;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }

        .finding {
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            page-break-inside: avoid;
            background: white;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #f1f5f9;
            padding-bottom: 15px;
            margin-bottom: 20px;
        }

        .finding-title {
            font-size: 20px;
            font-weight: 700;
            color: #0f172a;
            flex: 1;
            padding-right: 20px;
        }

        .severity-badge {
            padding: 6px 16px;
            border-radius: 999px;
            font-size: 11px;
            color: white;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            white-space: nowrap;
        }

        .label {
            font-weight: 700;
            color: #64748b;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 15px;
            display: block;
        }

        .value {
            color: #1e293b;
            font-size: 15px;
            font-weight: 500;
        }

        .code-block {
            background: #0f172a;
            color: #22d3ee;
            padding: 15px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 12px;
            margin-top: 8px;
            white-space: pre-wrap;
            border: 1px solid #334155;
        }

        .no-findings {
            text-align: center;
            padding: 60px;
            border: 2px dashed #e2e8f0;
            border-radius: 12px;
            color: #64748b;
        }

        @media print {
            body { background: white !important; }
            .cover { height: 100vh; page-break-after: always; }
            .page { padding: 0; width: 100%; max-width: none; }
            .finding { border: 1px solid #e2e8f0; box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="cover">
        <h1>SECURITY SCAN REPORT</h1>
        <h2>Target: ${targetInfo.target}</h2>
        <div class="cover-meta">
            <p style="margin: 0 0 10px 0; font-weight: 600;">Scan Name: <span style="color: var(--primary)">${targetInfo.scan_name}</span></p>
            <p style="margin: 0 0 10px 0; font-weight: 600;">Generated: ${dateStr}</p>
            <p style="margin: 0; font-weight: 600;">Tool: ${targetInfo.tool.toUpperCase()}</p>
        </div>
    </div>

    <div class="page">
        <div class="header">
            <h1>Executive Summary</h1>
            <span style="color: var(--muted); font-weight: 600;">${targetInfo.target}</span>
        </div>

        <div class="summary-box">
            <p style="margin-top: 0;">This document provides a comprehensive security assessment for <strong>${targetInfo.target}</strong>.</p>
            <p>During this scan, we identified <strong>${reportData.length}</strong> security findings categorized by severity as follows:</p>
            <div class="stats-grid">
                <div class="stat-card" style="background: var(--critical)">${severityCounts.Critical} CRITICAL</div>
                <div class="stat-card" style="background: var(--high)">${severityCounts.High} HIGH</div>
                <div class="stat-card" style="background: var(--medium)">${severityCounts.Medium} MEDIUM</div>
                <div class="stat-card" style="background: var(--low)">${severityCounts.Low} LOW</div>
            </div>
        </div>

        <h1 style="font-size: 24px; border-bottom: 2px solid #f1f5f9; padding-bottom: 10px; margin-top: 50px;">Detailed Vulnerability Findings</h1>

        ${reportData.length === 0 ? `
            <div class="no-findings">
                <h3>No vulnerabilities found</h3>
                <p>The security scan did not identify any known vulnerabilities on the specified target at this time.</p>
            </div>
        ` : reportData.map((f, i) => {
          const escapeHtml = (unsafe: string) => {
            if (!unsafe || typeof unsafe !== 'string') return '';
            return unsafe
              .replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
          };

          const primarySev = f.cve_details?.[0]?.cvss_v3_severity || 'INFO';

          return `
            <div class="finding">
                <div class="finding-header">
                    <span class="finding-title">${i + 1}. ${escapeHtml(f.vulnerability_name)}</span>
                    <span class="severity-badge" style="background: ${
                      primarySev === 'CRITICAL' ? 'var(--critical)' :
                      primarySev === 'HIGH' ? 'var(--high)' :
                      primarySev === 'MEDIUM' ? 'var(--medium)' : 'var(--low)'
                    }">${primarySev}</span>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <div>
                        <span class="label">Detection Path / Service</span>
                        <span class="value">${escapeHtml(f.service_info) || escapeHtml(f.finding_path) || 'N/A'}</span>
                    </div>
                    <div>
                        <span class="label">Finding Status</span>
                        <span class="value" style="text-transform: capitalize;">${f.finding_status}</span>
                    </div>
                </div>

                ${f.cve_details ? f.cve_details.map((cve: any) => `
                    <div style="margin-top: 25px; background: #f8fafc; border-radius: 8px; padding: 15px; border-left: 4px solid var(--primary);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <span class="label" style="color: var(--primary); margin-top: 0; font-size: 14px;">${cve.cve_id}</span>
                            <span style="font-size: 11px; background: #e2e8f0; padding: 2px 8px; border-radius: 4px; font-weight: 700; color: #475569;">
                                SCORE: ${cve.cvss_v3_score || 'N/A'}
                            </span>
                        </div>
                        <p class="value" style="font-size: 13px; color: #334155; margin-bottom: 10px;">${escapeHtml(cve.description)}</p>
                        <div style="font-size: 11px; color: #64748b; font-family: monospace;">
                            <strong>VECTOR:</strong> ${cve.cvss_v3_vector || 'N/A'}
                        </div>

                        ${cve.exploits && cve.exploits.length > 0 ? `
                            <span class="label" style="font-size: 11px; color: #ef4444;">Available Exploits:</span>
                            <ul class="value" style="font-size: 11px; padding-left: 20px; margin-top: 5px;">
                                ${cve.exploits.map((e: any) => `
                                    <li style="margin-bottom: 4px;">
                                        ${escapeHtml(e.title)}
                                        <a href="${escapeHtml(e.url)}" style="color: var(--primary); text-decoration: none; margin-left: 5px;">[Source]</a>
                                        ${e.verified ? '<span style="color: #10b981; font-weight: 700; margin-left: 5px;">(Verified)</span>' : ''}
                                    </li>`).join('')}
                            </ul>
                        ` : ''}

                        ${cve.references_urls && cve.references_urls.length > 0 ? `
                            <span class="label" style="font-size: 11px;">External References:</span>
                            <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 5px;">
                                ${cve.references_urls.slice(0, 3).map((url: string) => `
                                    <a href="${escapeHtml(url)}" style="font-size: 10px; color: var(--primary); background: white; border: 1px solid #e2e8f0; padding: 2px 6px; border-radius: 4px; text-decoration: none; white-space: nowrap; overflow: hidden; max-width: 200px; text-overflow: ellipsis;">${escapeHtml(url)}</a>
                                `).join('')}
                            </div>
                        ` : ''}
                    </div>
                `).join('') : '<p class="value" style="margin-top: 15px; font-style: italic; color: #94a3b8;">No CVE metadata associated with this finding.</p>'}

                ${f.finding_evidence ? `
                    <span class="label">Technical Evidence & Output</span>
                    <div class="code-block">${escapeHtml(f.finding_evidence)}</div>
                ` : ''}
            </div>
          `;
        }).join('')}
    </div>
    <script>
        window.onload = () => {
            setTimeout(() => {
                window.print();
                // Close the tab after print dialog is closed
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
                <strong className="text-foreground">{reportData.length} total findings</strong>. Full report available via export.
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
