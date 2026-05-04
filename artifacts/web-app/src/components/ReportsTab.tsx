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
        .from("scan_results")
        .select("id, name, target, created_at, status")
        .eq("status", "completed")
        .order("created_at", { ascending: false });

      if (userRole !== 'admin') {
        query = query.eq("user_id", user.id);
      }

      const { data, error } = await query;
      if (error) throw error;
      return data;
    },
  });

  const { data: reportData = [] } = useQuery({
    queryKey: ["target_report_data", selectedScanId, userRole],
    queryFn: async () => {
      if (selectedScanId === "all") return [];
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) return [];

      let query = supabase
        .from("target_report_data")
        .select("*")
        .eq("scan_id", selectedScanId);

      if (userRole !== 'admin') {
        query = query.eq("user_id", user.id);
      }

      const { data, error } = await query;
      if (error) throw error;
      return data;
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
    if (selectedScanId === "all" || reportData.length === 0) {
      toast.error("Please select a scan with findings to generate a report");
      return;
    }

    const targetInfo = reportData[0];
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
        body { font-family: 'Inter', system-ui, -apple-system, sans-serif; background: #fff; color: #1e293b; line-height: 1.5; padding: 0; margin: 0; }
        .page { padding: 40px; max-width: 900px; margin: 0 auto; background: white; }
        .header { border-bottom: 2px solid var(--primary); padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
        .header h1 { color: var(--primary); margin: 0; font-size: 24px; }
        .cover { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; background: var(--background); color: white; }
        .cover h1 { font-size: 48px; color: var(--primary); margin-bottom: 10px; }
        .cover h2 { font-size: 24px; color: var(--muted); margin-bottom: 40px; }
        .summary-box { background: #f1f5f9; border-radius: 8px; padding: 20px; margin-bottom: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }
        .stat-card { padding: 15px; border-radius: 6px; text-align: center; color: white; font-weight: bold; }
        .finding { border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 20px; page-break-inside: avoid; }
        .finding-header { display: flex; justify-content: space-between; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 15px; }
        .finding-title { font-size: 18px; font-weight: bold; color: #0f172a; }
        .severity-badge { padding: 4px 12px; border-radius: 999px; font-size: 12px; color: white; font-weight: bold; }
        .label { font-weight: bold; color: #64748b; font-size: 13px; margin-top: 10px; display: block; }
        .value { color: #1e293b; font-size: 14px; }
        .code-block { background: #1e293b; color: #06b6d4; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; margin-top: 5px; white-space: pre-wrap; }
        @media print {
            body { background: white !important; -webkit-print-color-adjust: exact; }
            .cover { height: auto; padding: 100px 0; page-break-after: always; }
        }
    </style>
</head>
<body>
    <div class="cover">
        <h1>SECURITY SCAN REPORT</h1>
        <h2>Target: ${targetInfo.target}</h2>
        <h3>Scan: ${targetInfo.scan_name}</h3>
        <p>Generated on ${dateStr}</p>
        <p style="margin-top: 50px;">Scan Tool: ${targetInfo.tool}</p>
    </div>

    <div class="page">
        <div class="header">
            <h1>Executive Summary</h1>
            <span style="color: var(--muted)">${targetInfo.target}</span>
        </div>

        <div class="summary-box">
            <p>This report summarizes the security findings for the target <strong>${targetInfo.target}</strong>. A total of <strong>${reportData.length}</strong> vulnerabilities were identified.</p>
            <div class="stats-grid">
                <div class="stat-card" style="background: var(--critical)">${severityCounts.Critical} Critical</div>
                <div class="stat-card" style="background: var(--high)">${severityCounts.High} High</div>
                <div class="stat-card" style="background: var(--medium)">${severityCounts.Medium} Medium</div>
                <div class="stat-card" style="background: var(--low)">${severityCounts.Low} Low</div>
            </div>
        </div>

        <h1>Detailed Findings</h1>
        ${reportData.map((f, i) => {
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
                        <span class="label">Service / Path</span>
                        <span class="value">${escapeHtml(f.service_info) || escapeHtml(f.finding_path) || 'N/A'}</span>
                    </div>
                    <div>
                        <span class="label">Status</span>
                        <span class="value">${f.finding_status}</span>
                    </div>
                </div>

                ${f.cve_details ? f.cve_details.map((cve: any) => `
                    <div style="margin-top: 15px; border-top: 1px dashed #e2e8f0; padding-top: 10px;">
                        <span class="label" style="color: var(--primary)">${cve.cve_id}</span>
                        <p class="value" style="font-size: 12px; margin-bottom: 5px;">${escapeHtml(cve.description)}</p>
                        <div style="font-size: 11px; color: #64748b;">
                            <strong>Score:</strong> ${cve.cvss_v3_score || 'N/A'} |
                            <strong>Vector:</strong> ${cve.cvss_v3_vector || 'N/A'}
                        </div>

                        ${cve.exploits ? `
                            <span class="label" style="font-size: 11px;">Known Exploits:</span>
                            <ul class="value" style="font-size: 11px;">
                                ${cve.exploits.map((e: any) => `<li>${escapeHtml(e.title)} - <a href="${escapeHtml(e.url)}">${escapeHtml(e.url)}</a></li>`).join('')}
                            </ul>
                        ` : ''}
                    </div>
                `).join('') : '<p class="value">No CVE details available.</p>'}

                ${f.finding_evidence ? `
                    <span class="label">Technical Evidence</span>
                    <div class="code-block">${escapeHtml(f.finding_evidence)}</div>
                ` : ''}
            </div>
          `;
        }).join('')}
    </div>
    <script>window.onload = () => { setTimeout(() => { window.print(); }, 500); }</script>
</body>
</html>`;
      const reportWindow = window.open('', '_blank');
      if (reportWindow) {
        reportWindow.document.write(html);
        reportWindow.document.close();
        toast.success("Report generated! Use the print dialog to Save as PDF.");
      } else {
        toast.error("Popup blocked! Please allow popups to view the report.");
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
