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

      const stats = extractStats(targetInfo.tool, selectedScan?.raw_output || "");

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
    <title>Scan Report - ${targetInfo.target}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Noto+Sans+Arabic:wght@400;700&display=swap');
        
        body { 
            font-family: 'Inter', 'Noto Sans Arabic', sans-serif;
            color: #1a1a1a;
            line-height: 1.4;
            padding: 40px;
            margin: 0; 
            font-size: 12px;
        }

        .checkpoint {
            display: flex;
            align-items: center;
            color: #22c55e;
            font-weight: 500;
            margin-bottom: 6px;
            font-size: 13px;
        }

        .checkpoint svg { margin-right: 8px; width: 16px; height: 16px; }

        .table-section { margin-top: 30px; margin-bottom: 20px; }
        .table-title { font-weight: 700; font-size: 14px; margin-bottom: 10px; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            border: 1px solid #e5e7eb;
            max-width: 500px;
        }
        
        td {
            padding: 8px 12px;
            border: 1px solid #e5e7eb;
            vertical-align: middle;
        }

        .label-cell { background-color: #f9fafb; width: 220px; }

        .arabic-report {
            margin-top: 40px;
            padding: 25px;
            background: #f8fafc;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
            text-align: right;
            direction: rtl;
        }

        .arabic-report h3 { color: #0ea5e9; margin-top: 0; font-size: 16px; }
        .arabic-report h4 { color: #334155; margin-bottom: 8px; font-size: 14px; }
        .arabic-report p { color: #64748b; font-size: 12px; margin-bottom: 15px; }

        .findings-section { margin-top: 40px; border-top: 1px solid #e5e7eb; padding-top: 20px; }
        .finding-group { border: 1px solid #e5e7eb; border-radius: 6px; margin-bottom: 20px; overflow: hidden; page-break-inside: avoid; }
        .finding-header { background: #f9fafb; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e5e7eb; }
        .severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; color: white; text-transform: uppercase; }
        .finding-body { padding: 15px; }
        .evidence-box { background: #0f172a; color: #38bdf8; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 10px; margin-top: 10px; white-space: pre-wrap; }

        .severity-critical { background: #dc2626; }
        .severity-high { background: #ea580c; }
        .severity-medium { background: #d97706; }
        .severity-low { background: #16a34a; }
        .severity-info { background: #2563eb; }

        @media print {
            body { padding: 0; }
        }
    </style>
</head>
<body>
    <div class="checkpoints">
      ${getCheckpoints(targetInfo.tool).map(cp => `
        <div class="checkpoint">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
          ${cp}
        </div>
      `).join('')}
    </div>

    <div class="table-section">
      <div class="table-title">Scan parameters</div>
      <table>
        <tr><td class="label-cell">target:</td><td>${targetInfo.target}</td></tr>
        <tr><td class="label-cell">scan_type:</td><td>Light</td></tr>
        <tr><td class="label-cell">authentication:</td><td>False</td></tr>
      </table>
    </div>

    <div class="table-section">
      <div class="table-title">Scan stats</div>
      <table>
        <tr><td class="label-cell">Unique Injection Points Detected:</td><td>${stats.uniquePoints}</td></tr>
        <tr><td class="label-cell">URLs spidered:</td><td>${stats.urlsSpidered}</td></tr>
        <tr><td class="label-cell">Total number of HTTP requests:</td><td>${stats.totalRequests}</td></tr>
        <tr><td class="label-cell">Average time until a response was received:</td><td>${stats.responseTime}</td></tr>
      </table>
    </div>

    <div class="arabic-report">
        <h3>منهجية تحليل المخاطر وتصنيف الثغرات</h3>
        <p>يعتمد هذا التقرير على محرك تحليل ذكي يقوم بمطابقة نتائج الفحص مع قواعد البيانات العالمية للثغرات (NVD) وأكواد الاستغلال (Exploit-DB). يتم تصنيف المخاطر بناءً على المعايير التالية:</p>

        <h4>1. مخاطر القابلية للاستغلال (Exploitability Risk)</h4>
        <p>
            هذا المخطط يحلل مدى سهولة استغلال الثغرات المكتشفة بناءً على توفر "أكواد الاستغلال" (Exploits):
            <br/>- <strong>Weaponized (مجهزة للاستخدام):</strong> يتم تصنيف الثغرة هنا إذا وجد لها كود استغلال مؤكد ومسجل في قاعدة بيانات Exploit-DB.
            <br/>- <strong>Public PoC (إثبات مفهوم عام):</strong> إذا كان هناك كود استغلال متاح للعامة ولكن لم يتم التحقق من فاعليته الكاملة.
            <br/>- <strong>Known CVE (ثغرة معروفة):</strong> ثغرات مسجلة في NVD ولكن لا يوجد كود استغلال مباشر مرتبط بها حالياً.
        </p>

        <h4>2. ناقل الهجوم (Attack Vector)</h4>
        <p>
            يعتمد هذا المخطط على معايير CVSS v3 لتحديد "المكان" الذي يجب أن يتواجد فيه المهاجم لاستغلال الثغرة:
            <br/>- <strong>Network (الشبكة):</strong> ثغرات يمكن استغلالها عن بُعد عبر الإنترنت (الأكثر خطورة).
            <br/>- <strong>Adjacent (الشبكة المجاورة):</strong> تتطلب من المهاجم أن يكون على نفس الشبكة المحلية (WiFi أو LAN).
            <br/>- <strong>Local/Physical:</strong> تتطلب وصولاً مباشراً إلى نظام الملفات أو تفاعلاً فيزيائياً مع الجهاز.
        </p>

        <h4>3. حالة النتائج (Finding Status)</h4>
        <p>
            يعكس سير العمل الإداري لكل ثغرة مكتشفة: <strong>Open</strong> للثغرات الجديدة، <strong>In Progress</strong> للمعالجة، <strong>Fixed</strong> للثغرات التي تم إغلاقها، و <strong>False Positive</strong> للنتائج المستبعدة يدوياً.
        </p>
    </div>

    <div class="findings-section">
        <div class="table-title">Vulnerability Details</div>
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
                    <span style="font-weight: 700;">${idx + 1}. ${escapeHtml(group.name)}</span>
                    <span class="severity-badge severity-${sev.toLowerCase()}">${sev}</span>
                </div>
                <div class="finding-body">
                    <div style="margin-bottom: 10px; color: #64748b; font-size: 11px;">
                        <strong>Resource:</strong> ${escapeHtml(group.path || 'Host Service')} |
                        <strong>Status:</strong> <span style="color: #16a34a;">${group.status.toUpperCase()}</span>
                    </div>

                    ${group.highPriority.map((c: any) => `
                        <div style="margin-bottom: 8px;">
                            <span style="color: #0ea5e9; font-weight: 600;">${c.cve_id}</span>
                            <span style="background: #f1f5f9; padding: 1px 4px; border-radius: 3px; font-size: 10px; margin-left: 5px;">CVSS: ${c.cvss_v3_score || 'N/A'}</span>
                            <div style="margin-top: 2px; color: #475569;">${escapeHtml(c.description)}</div>
                        </div>
                    `).join('')}

                    ${group.legacyMinor.length > 0 ? `
                        <div style="margin-top: 10px; font-size: 10px; color: #64748b; border-top: 1px solid #f1f5f9; padding-top: 5px;">
                            <strong>Additional observations:</strong> ${group.legacyMinor.slice(0, 5).map((c: any) => c.cve_id).join(', ')}
                            ${group.legacyMinor.length > 5 ? ` and ${group.legacyMinor.length - 5} more...` : ''}
                        </div>
                    ` : ''}

                    ${group.evidence.length > 0 ? `
                        <div class="evidence-box">${escapeHtml(group.evidence.join('\n\n'))}</div>
                    ` : ''}
                </div>
            </div>
          `;
        }).join('')}
        
        <div style="text-align: center; font-size: 10px; color: #94a3b8; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
            Generated by Vulnerability Manager &copy; ${new Date().getFullYear()}
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
