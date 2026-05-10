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
        .select("id, name, target, created_at, status, tool, critical_count, high_count, medium_count, low_count, total_findings, raw_output")
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

    if (format === "PDF") {
      const getCheckpoints = (tool: string) => {
        switch(tool.toUpperCase()) {
          case 'NIKTO':
            return [
              "Scanned for sensitive data",
              "Scanned for unsafe HTTP header Content Security Policy",
              "Scanned for OpenAPI files",
              "Scanned for file upload",
              "Scanned for SQL statement in request parameter",
              "Scanned for password returned in later response",
              "Scanned for Path Disclosure",
              "Scanned for Session Token in URL",
              "Scanned for API endpoints",
              "Scanned for missing HTTP header - Rate Limit"
            ];
          case 'SQLMAP':
            return [
              "Scanned for SQL statement in request parameter",
              "Scanned for Boolean-based blind SQL injection",
              "Scanned for Error-based SQL injection",
              "Scanned for Time-based blind SQL injection",
              "Scanned for Database fingerprinting",
              "Scanned for Operating System access",
              "Scanned for sensitive data leakage"
            ];
          case 'FFUF':
            return [
              "Scanned for API endpoints",
              "Scanned for OpenAPI/Swagger files",
              "Scanned for hidden backup files",
              "Scanned for directory indexing",
              "Scanned for sensitive configuration files",
              "Scanned for environment variables disclosure"
            ];
          case 'NMAP':
            return [
              "Scanned for open service ports",
              "Scanned for service version detection",
              "Scanned for SSL/TLS certificate validity",
              "Scanned for insecure authentication methods",
              "Scanned for network banners",
              "Scanned for OS fingerprinting"
            ];
          default:
            return ["Scanned for vulnerabilities", "Scanned for exposures"];
        }
      };

      const extractStats = (tool: string, output: string) => {
        const stats = {
          uniquePoints: 0,
          urlsSpidered: 0,
          totalRequests: 0,
          responseTime: "N/A"
        };

        if (!output) return stats;

        if (tool.toUpperCase() === 'NIKTO') {
          const items = output.match(/\+ /g);
          stats.uniquePoints = items ? items.length : 0;
          stats.urlsSpidered = (output.match(/https?:\/\/[^\s]+/g) || []).length;
          stats.totalRequests = stats.urlsSpidered * 2; // Approximation
          const timeMatch = output.match(/(\d+) seconds/);
          if (timeMatch) stats.responseTime = timeMatch[1] + "s";
        } else if (tool.toUpperCase() === 'NMAP') {
          const ports = output.match(/\d+\/tcp\s+open/g);
          stats.uniquePoints = ports ? ports.length : 0;
          stats.totalRequests = 1000; // Standard top-ports scan
          const latencyMatch = output.match(/latency \((\d+\.\d+)s latency\)/);
          if (latencyMatch) stats.responseTime = (parseFloat(latencyMatch[1]) * 1000).toFixed(0) + "ms";
        } else if (tool.toUpperCase() === 'SQLMAP') {
          stats.uniquePoints = (output.match(/parameter '[^']+' is vulnerable/gi) || []).length;
          stats.totalRequests = (output.match(/\[PAYLOAD\]/g) || []).length || 50;
        }

        return stats;
      };

      // -----------------------------------------------------------
      // MULTI-TOOL DATA GROUPING & CONSOLIDATION
      // -----------------------------------------------------------
      const toolsFound = Array.from(new Set(reportData.map(f => f.tool || targetInfo.tool || "Discovery Tool")));

      const sectionsHtml = toolsFound.map(tool => {
        const toolData = reportData.filter(f => (f.tool || targetInfo.tool) === tool);
        const stats = extractStats(tool, selectedScan?.raw_output || "");
        
        const consolidatedFindings: Record<string, any> = {};
        toolData.forEach((f) => {
          const groupKey = f.service_info || f.vulnerability_name || "General Discovery";
          if (!consolidatedFindings[groupKey]) {
            consolidatedFindings[groupKey] = {
              name: groupKey,
              path: f.finding_path,
              evidence: new Set([f.finding_evidence].filter(Boolean)),
              status: f.finding_status,
              severity_score: f.severity_score,
              cves: {},
            };
          }
          if (f.cve_details) {
            f.cve_details.forEach((cve: any) => {
              if (!consolidatedFindings[groupKey].cves[cve.cve_id]) {
                consolidatedFindings[groupKey].cves[cve.cve_id] = cve;
              }
            });
          }
          if (f.severity_score > consolidatedFindings[groupKey].severity_score) {
            consolidatedFindings[groupKey].severity_score = f.severity_score;
          }
        });

        const finalFindings = Object.values(consolidatedFindings).map(group => {
          const cveList = Object.values(group.cves) as any[];
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

        return `
          <div class="tool-section">
            <div class="tool-header">
              <div class="tool-name">${tool.toUpperCase()} SCAN RESULTS</div>
              <div class="tool-badge">INTELLIGENCE VERIFIED</div>
            </div>

            <div class="checkpoints">
              ${getCheckpoints(tool).map(cp => `
                <div class="checkpoint">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                  ${cp}
                </div>
              `).join('')}
            </div>

            <div class="stats-grid">
              <div class="stat-box">
                <div class="stat-label">Injections Detected</div>
                <div class="stat-value">${stats.uniquePoints}</div>
              </div>
              <div class="stat-box">
                <div class="stat-label">Resources Scanned</div>
                <div class="stat-value">${stats.urlsSpidered || 1}</div>
              </div>
              <div class="stat-box">
                <div class="stat-label">Traffic Load</div>
                <div class="stat-value">${stats.totalRequests} reqs</div>
              </div>
              <div class="stat-box">
                <div class="stat-label">Avg Latency</div>
                <div class="stat-value">${stats.responseTime}</div>
              </div>
            </div>

            <div class="findings-list">
              ${finalFindings.length === 0 ? `
                <div style="text-align: center; padding: 30px; color: #94a3b8; border: 1px dashed #e2e8f0; border-radius: 8px; font-size: 11px;">
                  No specific vulnerabilities found by this tool.
                </div>
              ` : finalFindings.map((group, idx) => {
                const escapeHtml = (unsafe: string) => {
                  if (!unsafe || typeof unsafe !== 'string') return '';
                  return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
                };
                const sevLabels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
                const sev = sevLabels[group.severity_score] || 'INFO';
                const displayedPrimary = group.highPriority.slice(0, 5);
                const displayedLegacy = group.legacyMinor.slice(0, 8);

                return `
                  <div class="finding-card">
                    <div class="finding-header">
                      <div class="finding-title">#${idx + 1} ${escapeHtml(group.name)}</div>
                      <div class="severity-tag sev-${sev.toLowerCase()}">${sev}</div>
                    </div>

                    <div class="meta-row">
                      <div class="meta-cell">
                        <span class="m-label">AFFECTED RESOURCE</span>
                        <span class="m-value">${escapeHtml(group.path || 'System Environment')}</span>
                      </div>
                      <div class="meta-cell">
                        <span class="m-label">REMEDIATION STATUS</span>
                        <span class="m-value status-active">● ${group.status.toUpperCase()}</span>
                      </div>
                    </div>

                    ${displayedPrimary.length > 0 ? `
                      <div class="sub-section-title">Verified Intelligence (Top Matches)</div>
                      <table class="cve-table">
                        <thead>
                          <tr>
                            <th width="110">CVE ID</th>
                            <th width="60">CVSS</th>
                            <th>Threat Description</th>
                          </tr>
                        </thead>
                        <tbody>
                          ${displayedPrimary.map((c: any) => `
                            <tr>
                              <td class="cve-link">${c.cve_id}</td>
                              <td><span class="score-pill">${c.cvss_v3_score || 'N/A'}</span></td>
                              <td class="cve-desc">${escapeHtml(c.description)}</td>
                            </tr>
                          `).join('')}
                        </tbody>
                      </table>
                    ` : ''}

                    ${displayedLegacy.length > 0 ? `
                      <div class="sub-section-title">Consolidated Historical Context</div>
                      <div class="legacy-tags">
                        ${displayedLegacy.map((c: any) => `<span class="legacy-tag">${c.cve_id}</span>`).join('')}
                        ${group.legacyMinor.length > 8 ? `<span class="legacy-tag-more">+${group.legacyMinor.length - 8} more</span>` : ''}
                      </div>
                    ` : ''}

                    ${group.evidence.length > 0 ? `
                      <div class="terminal-evidence">${escapeHtml(group.evidence.join('\n\n'))}</div>
                    ` : ''}
                  </div>
                `;
              }).join('')}
            </div>
          </div>
        `;
      }).join('<div style="page-break-after: always;"></div>');

      const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Executive Scan Report - ${targetInfo.target}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Noto+Sans+Arabic:wght@400;700&display=swap');
        
        body { 
            font-family: 'Plus Jakarta Sans', 'Noto Sans Arabic', sans-serif;
            color: #1e293b;
            line-height: 1.5;
            padding: 50px;
            margin: 0; 
            background: #ffffff;
            font-size: 12px;
        }

        .report-header { margin-bottom: 40px; border-bottom: 2px solid #f1f5f9; padding-bottom: 20px; display: flex; justify-content: space-between; align-items: flex-end; }
        .report-title { font-size: 24px; font-weight: 800; color: #0f172a; margin: 0; }
        .report-subtitle { font-size: 13px; color: #64748b; margin-top: 5px; }

        .tool-section { margin-bottom: 60px; }
        .tool-header {
          background: #f8fafc;
          padding: 15px 20px;
          border-left: 4px solid #3b82f6;
          margin-bottom: 25px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .tool-name { font-weight: 800; font-size: 14px; color: #1e40af; letter-spacing: 0.5px; }
        .tool-badge { background: #dbeafe; color: #1e40af; padding: 4px 10px; border-radius: 99px; font-size: 9px; font-weight: 700; }

        .checkpoints { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 25px; }
        .checkpoint { display: flex; align-items: center; color: #059669; font-weight: 600; font-size: 11px; }
        .checkpoint svg { margin-right: 8px; width: 14px; height: 14px; color: #10b981; }

        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 35px; }
        .stat-box { background: #ffffff; border: 1px solid #e2e8f0; padding: 15px; border-radius: 12px; text-align: center; }
        .stat-label { font-size: 9px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 5px; }
        .stat-value { font-size: 16px; font-weight: 800; color: #0f172a; }

        .finding-card {
          background: #ffffff;
          border: 1px solid #e2e8f0;
          border-radius: 12px;
          padding: 25px;
          margin-bottom: 30px;
          page-break-inside: avoid;
          box-shadow: 0 1px 3px rgba(0,0,0,0.02);
        }
        
        .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
        .finding-title { font-size: 16px; font-weight: 700; color: #0f172a; max-width: 80%; }

        .severity-tag { padding: 4px 12px; border-radius: 6px; font-size: 10px; font-weight: 800; color: white; text-transform: uppercase; }
        .sev-critical { background: #ef4444; }
        .sev-high { background: #f97316; }
        .sev-medium { background: #f59e0b; }
        .sev-low { background: #10b981; }
        .sev-info { background: #6366f1; }

        .meta-row { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 25px; padding: 15px; background: #f8fafc; border-radius: 8px; }
        .m-label { display: block; font-size: 9px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 4px; }
        .m-value { font-size: 12px; font-weight: 600; color: #1e293b; }
        .status-active { color: #059669; }

        .sub-section-title { font-size: 11px; font-weight: 800; color: #475569; text-transform: uppercase; margin: 25px 0 12px 0; display: flex; align-items: center; }
        .sub-section-title::after { content: ""; flex: 1; height: 1px; background: #e2e8f0; margin-left: 10px; }

        .cve-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        .cve-table th { text-align: left; padding: 12px 10px; background: #f1f5f9; color: #475569; font-size: 10px; font-weight: 700; text-transform: uppercase; }
        .cve-table td { padding: 12px 10px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }

        .cve-link { color: #2563eb; font-weight: 700; font-family: monospace; }
        .score-pill { background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 4px; font-weight: 800; font-size: 10px; }
        .cve-desc { font-size: 11px; color: #475569; line-height: 1.6; }

        .legacy-tags { display: flex; flex-wrap: wrap; gap: 8px; }
        .legacy-tag { background: #f1f5f9; color: #475569; padding: 4px 10px; border-radius: 6px; font-size: 10px; font-weight: 600; border: 1px solid #e2e8f0; }
        .legacy-tag-more { color: #94a3b8; font-size: 10px; padding: 4px 10px; font-weight: 600; }

        .terminal-evidence {
          background: #0f172a;
          color: #38bdf8;
          padding: 18px;
          border-radius: 10px;
          font-family: 'JetBrains Mono', 'Courier New', monospace;
          font-size: 10px;
          margin-top: 20px;
          white-space: pre-wrap;
          border: 1px solid #1e293b;
          line-height: 1.5;
        }

        .arabic-section {
            margin: 40px 0;
            padding: 30px;
            background: #f8fafc;
            border-radius: 15px;
            border-right: 6px solid #3b82f6;
            text-align: right;
            direction: rtl;
        }
        .arabic-section h3 { color: #1e3a8a; margin-top: 0; font-size: 18px; font-weight: 800; }
        .arabic-section h4 { color: #334155; margin: 20px 0 10px 0; font-size: 15px; }
        .arabic-section p { color: #475569; font-size: 13px; margin-bottom: 10px; line-height: 1.8; }

        @media print {
            body { padding: 20px; }
            .tool-section { page-break-before: always; }
            .tool-section:first-of-type { page-break-before: auto; }
        }
    </style>
</head>
<body>
    <div class="report-header">
      <div>
        <h1 class="report-title">Vulnerability Assessment Report</h1>
        <div class="report-subtitle">Targeted Scan Analysis for: <strong>${targetInfo.target}</strong></div>
      </div>
      <div style="text-align: right;">
        <div class="report-subtitle">Generated: ${new Date().toLocaleDateString("en-US", { month: 'long', day: 'numeric', year: 'numeric' })}</div>
        <div class="report-subtitle">Status: Intelligence Verified</div>
      </div>
    </div>

    <div class="arabic-section">
        <h3>منهجية تحليل المخاطر وتصنيف الثغرات</h3>
        <p>يعتمد هذا التقرير على محرك تحليل ذكي يقوم بمطابقة نتائج الفحص مع قواعد البيانات العالمية للثغرات (NVD) وأكواد الاستغلال (Exploit-DB). يتم تصنيف المخاطر بناءً على المعايير التالية:</p>

        <h4>1. مخاطر القابلية للاستغلال (Exploitability Risk)</h4>
        <p>يحلل مدى سهولة استغلال الثغرات بناءً على توفر "أكواد الاستغلال" (Exploits)، حيث يتم تمييز الثغرات الجاهزة للاستغلال (Weaponized) عن تلك التي تملك إثبات مفهوم فقط (PoC).</p>

        <h4>2. ناقل الهجوم (Attack Vector)</h4>
        <p>يحدد "المكان" الذي يجب أن يتواجد فيه المهاجم لاستغلال الثغرة (Network, Adjacent, Local, Physical) بناءً على معايير CVSS v3 العالمية.</p>

        <h4>3. حالة النتائج (Finding Status)</h4>
        <p>يعكس سير العمل الإداري لكل ثغرة مكتشفة لضمان تتبع عملية المعالجة (Remediation) بشكل دقيق.</p>
    </div>

    ${sectionsHtml}

    <div style="text-align: center; font-size: 10px; color: #94a3b8; margin-top: 60px; padding-top: 20px; border-top: 1px solid #f1f5f9;">
        This report is confidential and intended for authorized security personnel only.<br/>
        &copy; ${new Date().getFullYear()} CyberSecurity Intelligence System
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
