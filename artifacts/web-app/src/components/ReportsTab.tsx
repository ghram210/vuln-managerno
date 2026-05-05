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
            line-height: 1.6;
            padding: 0;
            margin: 0;
            -webkit-print-color-adjust: exact;
        }

        .page {
            padding: 40px 50px;
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            position: relative;
        }

        .page-break { page-break-before: always; }

        .header-main {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }

        .header-main .logo {
            font-size: 24px;
            font-weight: 800;
            color: var(--primary);
            letter-spacing: -0.05em;
        }

        .header-main .target-url {
            color: var(--text-muted);
            font-size: 14px;
            font-weight: 500;
        }

        .cover {
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: white;
            position: relative;
            overflow: hidden;
        }

        .cover::before {
            content: "";
            position: absolute;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle at center, rgba(14, 165, 233, 0.1) 0%, transparent 40%);
            top: -50%;
            left: -50%;
        }

        .cover-content {
            z-index: 10;
            max-width: 800px;
        }

        .report-badge {
            display: inline-block;
            background: rgba(14, 165, 233, 0.15);
            color: var(--primary);
            padding: 8px 20px;
            border-radius: 99px;
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 30px;
            border: 1px solid rgba(14, 165, 233, 0.3);
        }

        .cover h1 {
            font-size: 64px;
            font-weight: 800;
            line-height: 1.1;
            margin-bottom: 20px;
            letter-spacing: -0.04em;
            background: linear-gradient(to bottom, #fff, #94a3b8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .cover-meta {
            margin-top: 60px;
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 30px;
            text-align: left;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            padding-top: 40px;
        }

        .meta-item .label { color: #94a3b8; font-size: 12px; margin-bottom: 8px; text-transform: uppercase; font-weight: 700; }
        .meta-item .value { color: #f8fafc; font-size: 18px; font-weight: 600; }

        .summary-card {
            background: #fff;
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 35px;
            margin-bottom: 40px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }

        .section-title {
            font-size: 28px;
            font-weight: 800;
            color: var(--bg-dark);
            margin-bottom: 30px;
            letter-spacing: -0.02em;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .section-title::before {
            content: "";
            width: 4px;
            height: 28px;
            background: var(--primary);
            border-radius: 4px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-top: 30px;
        }

        .stat-card {
            padding: 20px 10px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid var(--border);
        }

        .stat-card .count { font-size: 28px; font-weight: 800; display: block; margin-bottom: 4px; }
        .stat-card .label { font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }

        .stat-critical { border-bottom: 4px solid var(--critical); }
        .stat-high { border-bottom: 4px solid var(--high); }
        .stat-medium { border-bottom: 4px solid var(--medium); }
        .stat-low { border-bottom: 4px solid var(--low); }
        .stat-total { background: var(--bg-dark); border: none; }
        .stat-total .count, .stat-total .label { color: white; }

        .finding {
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 0;
            margin-bottom: 40px;
            page-break-inside: avoid;
            background: white;
            overflow: hidden;
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f8fafc;
            padding: 20px 30px;
            border-bottom: 1px solid var(--border);
        }

        .finding-title {
            font-size: 18px;
            font-weight: 700;
            color: var(--bg-dark);
        }

        .severity-pill {
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 12px;
            color: white;
            font-weight: 800;
            text-transform: uppercase;
        }

        .finding-body { padding: 30px; }

        .details-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 25px;
            margin-bottom: 30px;
        }

        .detail-item .label { font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 5px; display: block; }
        .detail-item .value { font-size: 14px; font-weight: 600; color: var(--text-main); word-break: break-all; }

        .code-container {
            background: #1e293b;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 12px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            margin-top: 10px;
            white-space: pre-wrap;
            border: 1px solid #334155;
            position: relative;
        }

        .code-container::before {
            content: "TECHNICAL EVIDENCE";
            position: absolute;
            top: -10px;
            left: 20px;
            background: #0ea5e9;
            color: white;
            font-size: 9px;
            font-weight: 800;
            padding: 2px 8px;
            border-radius: 4px;
        }

        .cve-card {
            background: #f0f9ff;
            border: 1px solid #bae6fd;
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
        }

        .exploit-tag {
            display: inline-flex;
            align-items: center;
            background: #fef2f2;
            color: #dc2626;
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 4px;
            border: 1px solid #fee2e2;
            margin-top: 10px;
        }

        .no-findings {
            text-align: center;
            padding: 80px 40px;
            background: #f8fafc;
            border: 2px dashed var(--border);
            border-radius: 20px;
            color: var(--text-muted);
        }

        @media print {
            body { background: white !important; }
            .cover { height: 100vh; page-break-after: always; -webkit-print-color-adjust: exact; }
            .page { padding: 0; width: 100%; max-width: none; }
            .finding { border: 1px solid var(--border); box-shadow: none; page-break-inside: avoid; }
            .footer { position: fixed; bottom: 0; width: 100%; text-align: center; font-size: 10px; color: var(--text-muted); }
        }
    </style>
</head>
<body>
    <div class="cover">
        <div class="cover-content">
            <div class="report-badge">Security Assessment</div>
            <h1>Vulnerability Analysis Report</h1>
            <p style="font-size: 20px; color: #94a3b8; margin-bottom: 40px;">Comprehensive scan of ${targetInfo.target}</p>

            <div class="cover-meta">
                <div class="meta-item">
                    <div class="label">Target Asset</div>
                    <div class="value">${targetInfo.target}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Report Date</div>
                    <div class="value">${dateStr}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Scan Tool</div>
                    <div class="value">${targetInfo.tool.toUpperCase()}</div>
                </div>
            </div>
        </div>
    </div>

    <div class="page">
        <div class="header-main">
            <div class="logo">PENTEST-PRO</div>
            <div class="target-url">${targetInfo.target}</div>
        </div>

        <h2 class="section-title">Executive Summary</h2>

        <div class="summary-card">
            <p style="font-size: 16px; margin-bottom: 30px;">
                This security assessment was performed on <strong>${targetInfo.target}</strong> using <strong>${targetInfo.tool}</strong>.
                The analysis identified a total of <strong>${severityCounts.Total}</strong> security findings with varying risk levels.
            </p>

            <div style="margin-bottom: 40px;">
                <div style="font-size: 12px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 15px; letter-spacing: 0.05em;">Risk Distribution</div>
                <div style="display: flex; height: 32px; border-radius: 8px; overflow: hidden; background: #f1f5f9;">
                    ${severityCounts.Critical > 0 ? `<div style="width: ${(severityCounts.Critical / severityCounts.Total) * 100}%; background: var(--critical); border-right: 2px solid white;"></div>` : ''}
                    ${severityCounts.High > 0 ? `<div style="width: ${(severityCounts.High / severityCounts.Total) * 100}%; background: var(--high); border-right: 2px solid white;"></div>` : ''}
                    ${severityCounts.Medium > 0 ? `<div style="width: ${(severityCounts.Medium / severityCounts.Total) * 100}%; background: var(--medium); border-right: 2px solid white;"></div>` : ''}
                    ${severityCounts.Low > 0 ? `<div style="width: ${(severityCounts.Low / severityCounts.Total) * 100}%; background: var(--low); border-right: 2px solid white;"></div>` : ''}
                    ${(severityCounts.Total === 0) ? `<div style="width: 100%; background: #e2e8f0;"></div>` : ''}
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card stat-total">
                    <span class="count">${severityCounts.Total}</span>
                    <span class="label">Total</span>
                </div>
                <div class="stat-card stat-critical">
                    <span class="count" style="color: var(--critical)">${severityCounts.Critical}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="stat-card stat-high">
                    <span class="count" style="color: var(--high)">${severityCounts.High}</span>
                    <span class="label">High</span>
                </div>
                <div class="stat-card stat-medium">
                    <span class="count" style="color: var(--medium)">${severityCounts.Medium}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="stat-card stat-low">
                    <span class="count" style="color: var(--low)">${severityCounts.Low}</span>
                    <span class="label">Low</span>
                </div>
            </div>
        </div>

        <h2 class="section-title page-break" style="margin-top: 60px;">Detailed Vulnerability Findings</h2>

        ${reportData.length === 0 ? (severityCounts.Total > 0 ? `
            <div class="no-findings">
                <h3>Technical Details Limited</h3>
                <p>The scan identified <strong>${severityCounts.Total}</strong> findings, but detailed report data is still being processed or RLS policies are restricting access. Please ensure you have permission to view these findings.</p>
            </div>
        ` : `
            <div class="no-findings">
                <h3>No Vulnerabilities Detected</h3>
                <p>The security scan did not identify any known vulnerabilities on the specified target asset at this time.</p>
            </div>
        `) : reportData.map((f, i) => {
          const escapeHtml = (unsafe: string) => {
            if (!unsafe || typeof unsafe !== 'string') return '';
            return unsafe
              .replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
          };

          const severityLabels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
          const primarySev = severityLabels[f.severity_score] || 'INFO';

          const remediationDays =
            primarySev === 'CRITICAL' ? 7 :
            primarySev === 'HIGH' ? 30 :
            primarySev === 'MEDIUM' ? 90 : 180;

          return `
            <div class="finding">
                <div class="finding-header">
                    <span class="finding-title">${i + 1}. ${escapeHtml(f.vulnerability_name)}</span>
                    <span class="severity-pill" style="background: ${
                      primarySev === 'CRITICAL' ? 'var(--critical)' :
                      primarySev === 'HIGH' ? 'var(--high)' :
                      primarySev === 'MEDIUM' ? 'var(--medium)' :
                      primarySev === 'LOW' ? 'var(--low)' : 'var(--info)'
                    }">${primarySev}</span>
                </div>

                <div class="finding-body">
                    <div class="details-grid">
                        <div class="detail-item">
                            <span class="label">Impacted Resource</span>
                            <span class="value">${escapeHtml(f.service_info) || escapeHtml(f.finding_path) || 'Network/Server'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Status</span>
                            <span class="value" style="color: ${f.finding_status === 'open' ? 'var(--critical)' : 'var(--low)'}; text-transform: uppercase; font-size: 12px;">
                                ${f.finding_status}
                            </span>
                        </div>
                        <div class="detail-item">
                            <span class="label">Remediation Window</span>
                            <span class="value">${remediationDays} Days</span>
                        </div>
                    </div>

                    <div style="margin-bottom: 25px;">
                        <span class="label">Recommended Action</span>
                        <p class="value" style="font-size: 14px; margin-top: 5px;">
                            ${primarySev === 'CRITICAL' || primarySev === 'HIGH' ?
                                `Apply security patches immediately. Restrict network access to the affected service until remediated.` :
                                `Schedule remediation within the ${remediationDays}-day window. Monitor for exploit attempts in logs.`}
                        </p>
                    </div>

                    ${f.cve_details ? f.cve_details.map((cve: any) => `
                        <div class="cve-card">
                            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                                <span style="font-weight: 800; color: var(--primary); font-size: 16px;">${cve.cve_id}</span>
                                <div style="text-align: right;">
                                    <div style="font-size: 10px; font-weight: 700; color: var(--text-muted);">CVSS v3.1</div>
                                    <div style="font-size: 18px; font-weight: 800; color: var(--bg-dark);">${cve.cvss_v3_score || 'N/A'}</div>
                                </div>
                            </div>

                            <p style="font-size: 14px; color: var(--text-main); margin-bottom: 15px; border-left: 3px solid var(--border); padding-left: 15px;">
                                ${escapeHtml(cve.description)}
                            </p>

                            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 15px;">
                                <div style="font-size: 11px; color: var(--text-muted); background: white; padding: 4px 10px; border-radius: 4px; border: 1px solid var(--border);">
                                    <strong>Vector:</strong> ${cve.cvss_v3_vector || 'N/A'}
                                </div>
                            </div>

                            ${cve.exploits && cve.exploits.length > 0 ? `
                                <div style="margin-top: 20px; padding: 15px; background: #fff1f2; border: 1px solid #fecdd3; border-radius: 8px;">
                                    <div style="font-size: 12px; font-weight: 800; color: #be123c; text-transform: uppercase; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;">
                                        <span style="display: inline-block; width: 8px; height: 8px; background: #be123c; border-radius: 50%;"></span>
                                        Real Exploit Intelligence Identified
                                    </div>

                                    ${cve.exploits.map((ex: any) => `
                                        <div style="margin-bottom: 15px; last-child: margin-bottom: 0;">
                                            <div style="display: flex; gap: 10px; margin-bottom: 8px;">
                                                <span style="font-size: 11px; font-weight: 700; background: #be123c; color: white; padding: 2px 6px; border-radius: 4px;">${escapeHtml(ex.type || 'EXPLOIT')}</span>
                                                <span style="font-size: 11px; font-weight: 700; background: #475569; color: white; padding: 2px 6px; border-radius: 4px;">${escapeHtml(ex.platform || 'General')}</span>
                                                ${ex.verified ? '<span style="font-size: 11px; font-weight: 700; background: #16a34a; color: white; padding: 2px 6px; border-radius: 4px;">VERIFIED</span>' : ''}
                                            </div>
                                            <p style="font-size: 13px; font-weight: 600; color: #1e293b; margin: 5px 0;">${escapeHtml(ex.title)}</p>
                                            ${ex.description ? `
                                                <div style="font-size: 12px; color: #475569; background: white; padding: 10px; border-radius: 6px; border: 1px solid #e2e8f0; margin-top: 5px; font-family: 'JetBrains Mono', monospace; white-space: pre-wrap;">${escapeHtml(ex.description)}</div>
                                            ` : ''}
                                            <a href="${escapeHtml(ex.url)}" style="font-size: 11px; color: #be123c; text-decoration: underline; margin-top: 5px; display: inline-block;">View technical proof on ExploitDB</a>
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''}

                            ${cve.references_urls && cve.references_urls.length > 0 ? `
                                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px dashed var(--border);">
                                    <span class="label">Technical References</span>
                                    <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 5px;">
                                        ${cve.references_urls.slice(0, 5).map((url: string) => {
                                            let hostname = "Reference";
                                            try { hostname = new URL(url).hostname; } catch(e) {}
                                            return `
                                            <a href="${escapeHtml(url)}" style="font-size: 10px; color: var(--primary); text-decoration: none; background: white; padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border);">
                                                ${escapeHtml(hostname)}
                                            </a>`;
                                        }).join('')}
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    `).join('') : ''}

                    ${f.finding_evidence ? `
                        <div style="margin-top: 25px;">
                            <span class="label">Evidence</span>
                            <div class="code-container">${escapeHtml(f.finding_evidence)}</div>
                        </div>
                    ` : ''}
                </div>
            </div>
          `;
        }).join('')}
    </div>
    <div class="footer">
        Generated by Pentest-Pro Security Platform &copy; ${new Date().getFullYear()}
    </div>

    <script>
        window.onload = () => {
            setTimeout(() => {
                window.print();
                window.onafterprint = () => window.close();
            }, 800);
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
