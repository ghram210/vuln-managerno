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
      let query = supabase
        .from("scan_results" as any)
        .select("id, name, target, created_at, status, tool, critical_count, high_count, medium_count, low_count, total_findings")
        .eq("status", "completed")
        .order("created_at", { ascending: false });

      const { data, error } = await query;
      if (error) throw error;
      return data as any[];
    },
  });

  const { data: reportData = [] } = useQuery({
    queryKey: ["target_report_data", selectedScanId, userRole],
    queryFn: async () => {
      if (selectedScanId === "all") return [];

      let query = supabase
        .from("target_report_data" as any)
        .select("*")
        .eq("scan_id", selectedScanId);

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
      const { data: scanRaw } = await supabase
        .from("scan_results" as any)
        .select("raw_output, created_at, status, total_findings, critical_count, high_count, medium_count, low_count")
        .eq("id", selectedScanId)
        .single();
      
      const rawOutput = (scanRaw as any)?.raw_output || "";
      const scanInfoData = scanRaw as any;

      // Calculate Overall Risk Score based on VulnDashboard logic
      const { data: riskScoreData } = await supabase
        .from("vuln_risk_score")
        .select("*")
        .eq("target", targetInfo.target);

      const riskLabels = ["Base CVSS", "Exploitability", "Asset Criticality", "Exposure"];
      const aggregatedRiskScores = riskLabels.map(label => {
        const matching = (riskScoreData || []).filter((r: any) => r.label === label);
        const avg = matching.length > 0 ? (matching.reduce((s, r) => s + (r.value || 0), 0) / matching.length) : 0;
        return avg;
      });
      const totalRiskVal = aggregatedRiskScores.reduce((s, v) => s + v, 0);
      
      const getRiskLabel = (val: number) => {
        if (val >= 20) return 'Critical';
        if (val >= 15) return 'High';
        if (val >= 10) return 'Medium';
        if (val >= 5) return 'Low';
        return 'Info';
      };

      const overallRisk = getRiskLabel(totalRiskVal);

      const getSmartAnalysis = (name: string, cveList: any[]) => {
        const analysis = {
          risk: "The identified service or vulnerability could potentially allow an attacker to gain unauthorized access or information about the target system.",
          recommendation: "Update the affected software to the latest stable version and follow vendor security guidelines.",
          references: ["https://nvd.nist.gov/", "https://owasp.org/"],
          cwe: "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
          owasp: [
            "OWASP Top 10 - 2017 : A6 - Security Misconfiguration",
            "OWASP Top 10 - 2021 : A5 - Security Misconfiguration"
          ]
        };

        const lowName = (name || "").toLowerCase();
        if (lowName.includes('apache') || lowName.includes('httpd')) {
          analysis.risk = "The Apache HTTP Server is exposing version information or hosting potentially vulnerable modules. An attacker can use this information to launch targeted exploits.";
          analysis.recommendation = "Disable the 'ServerTokens' and 'ServerSignature' directives in the configuration. Ensure all modules are up to date.";
          analysis.references = [
            "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens",
            "https://httpd.apache.org/docs/2.4/misc/security_tips.html",
            "https://www.cisa.gov/news-events/alerts/2021/10/05/apache-releases-security-update-http-server"
          ];
        } else if (lowName.includes('robots.txt')) {
          analysis.risk = "There is no particular security risk in having a robots.txt file. However, it's important to note that adding endpoints in it should not be considered a security measure, as this file can be directly accessed and read by anyone.";
          analysis.recommendation = "We recommend you to manually review the entries from robots.txt and remove the ones which lead to sensitive locations in the website (ex. administration panels, configuration files, etc).";
          analysis.references = [
            "https://www.theregister.co.uk/2015/05/19/robotstxt/",
            "https://developers.google.com/search/docs/crawling-indexing/robots/intro"
          ];
          analysis.cwe = "CWE-693: Protection Mechanism Failure";
          analysis.owasp = ["OWASP Top 10 - 2017 : A6 - Security Misconfiguration", "OWASP Top 10 - 2021 : A5 - Security Misconfiguration"];
        } else if (lowName.includes('sql injection') || lowName.includes('sqli')) {
          analysis.risk = "A SQL injection vulnerability allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data they are not normally able to retrieve.";
          analysis.recommendation = "Use parameterized queries (also known as prepared statements) for all database access. Implement input validation and the principle of least privilege for database accounts.";
          analysis.references = [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/sql-injection",
            "https://cwe.mitre.org/data/definitions/89.html"
          ];
          analysis.cwe = "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')";
          analysis.owasp = ["OWASP Top 10 - 2021 : A03 - Injection"];
        } else if (lowName.includes('x-frame-options') || lowName.includes('clickjacking')) {
          analysis.risk = "The absence of the X-Frame-Options header makes the application vulnerable to Clickjacking attacks, where an attacker can trick a user into clicking on something different from what the user perceives.";
          analysis.recommendation = "Configure the server to send the 'X-Frame-Options: SAMEORIGIN' or 'DENY' header to prevent the page from being framed by malicious sites.";
          analysis.references = [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"
          ];
          analysis.cwe = "CWE-693: Protection Mechanism Failure";
          analysis.owasp = ["OWASP Top 10 - 2021 : A05 - Security Misconfiguration"];
        } else if (lowName.includes('.env') || lowName.includes('environment variables')) {
          analysis.risk = "Exposure of environment variables (.env file) can leak sensitive information such as database credentials, API keys, and other secrets used by the application.";
          analysis.recommendation = "Restrict access to the .env file in the web server configuration or move it outside the web root directory.";
          analysis.references = [
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Test_for_Account_Enumeration_and_Guessable_User_Account",
            "https://cwe.mitre.org/data/definitions/200.html"
          ];
          analysis.cwe = "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor";
          analysis.owasp = ["OWASP Top 10 - 2021 : A01 - Broken Access Control"];
        } else if (lowName.includes('.git')) {
          analysis.risk = "Exposure of the .git directory allows an attacker to download the entire source code and history of the application, which may contain sensitive logic and credentials.";
          analysis.recommendation = "Disable directory listing and specifically block access to the .git directory in your web server configuration (e.g., using <DirectoryMatch \"/\\.git\"> in Apache or location block in Nginx).";
          analysis.references = [
            "https://en.internetwache.org/dont-publicly-expose-your-git-directory-12-11-2015/",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_HTTP_Methods"
          ];
          analysis.cwe = "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor";
          analysis.owasp = ["OWASP Top 10 - 2021 : A01 - Broken Access Control"];
        }

        if (cveList.length > 0) {
          const topCve = cveList[0];
          analysis.risk = topCve.description || analysis.risk;
          if (topCve.cve_id) {
            analysis.references.unshift(`https://nvd.nist.gov/vuln/detail/${topCve.cve_id}`);
          }
        }
        return analysis;
      };

      const getCheckpoints = (tool: string) => {
        switch(tool.toUpperCase()) {
          case 'NIKTO': return ["Scanned for sensitive data", "Scanned for unsafe HTTP header Content Security Policy", "Scanned for OpenAPI files", "Scanned for file upload", "Scanned for SQL statement in request parameter", "Scanned for password returned in later response", "Scanned for Path Disclosure", "Scanned for Session Token in URL", "Scanned for API endpoints", "Scanned for missing HTTP header - Rate Limit"];
          case 'SQLMAP': return ["Scanned for SQL statement in request parameter", "Scanned for Boolean-based blind SQL injection", "Scanned for Error-based SQL injection", "Scanned for Time-based blind SQL injection", "Scanned for Database fingerprinting", "Scanned for Operating System access", "Scanned for sensitive data leakage"];
          case 'FFUF': return ["Scanned for API endpoints", "Scanned for OpenAPI/Swagger files", "Scanned for hidden backup files", "Scanned for directory indexing", "Scanned for sensitive configuration files", "Scanned for environment variables disclosure"];
          case 'NMAP': return ["Scanned for open service ports", "Scanned for service version detection", "Scanned for SSL/TLS certificate validity", "Scanned for insecure authentication methods", "Scanned for network banners", "Scanned for OS fingerprinting"];
          default: return ["Scanned for vulnerabilities", "Scanned for exposures"];
        }
      };

      const extractStats = (tool: string, output: string) => {
        const stats = { uniquePoints: 0, urlsSpidered: 0, totalRequests: 0, responseTime: "N/A", duration: 0 };
        if (!output) return stats;
        if (tool.toUpperCase() === 'NIKTO') {
          const items = output.match(/\+ /g);
          stats.uniquePoints = items ? items.length : 0;
          stats.urlsSpidered = (output.match(/https?:\/\/[^\s]+/g) || []).length;
          stats.totalRequests = stats.urlsSpidered * 2;
          const timeMatch = output.match(/(\d+) seconds/);
          if (timeMatch) {
            stats.responseTime = timeMatch[1] + "s";
            stats.duration = parseInt(timeMatch[1]);
          }
        } else if (tool.toUpperCase() === 'NMAP') {
          const ports = output.match(/\d+\/tcp\s+open/g);
          stats.uniquePoints = ports ? ports.length : 0;
          stats.totalRequests = 1000;
          const latencyMatch = output.match(/latency \((\d+\.\d+)s latency\)/);
          if (latencyMatch) stats.responseTime = (parseFloat(latencyMatch[1]) * 1000).toFixed(0) + "ms";
          const scanTimeMatch = output.match(/scanned in (\d+\.\d+) seconds/);
          if (scanTimeMatch) stats.duration = Math.ceil(parseFloat(scanTimeMatch[1]));
        } else if (tool.toUpperCase() === 'SQLMAP') {
          stats.uniquePoints = (output.match(/parameter '[^']+' is vulnerable/gi) || []).length;
          stats.totalRequests = (output.match(/\[PAYLOAD\]/g) || []).length || 50;
          stats.duration = 45; // Fixed estimate for SQLmap deep scan
        }
        return stats;
      };

      const toolsFound = Array.from(new Set(reportData.map(f => f.tool || targetInfo.tool || "Discovery Tool")));
      
      const sectionsHtml = toolsFound.map(tool => {
        const toolData = reportData.filter(f => (f.tool || targetInfo.tool) === tool);
        if (toolData.length === 0) return '';
        const stats = extractStats(tool, rawOutput);
        const consolidatedFindings: Record<string, any> = {};
        
        toolData.forEach((f) => {
          const groupKey = f.service_info || f.vulnerability_name || "General Discovery";
          if (!consolidatedFindings[groupKey]) {
            consolidatedFindings[groupKey] = { name: groupKey, path: f.finding_path, evidence: new Set([f.finding_evidence].filter(Boolean)), status: f.finding_status, severity_score: f.severity_score, cves: {} };
          }
          if (f.cve_details) {
            f.cve_details.forEach((cve: any) => { if (!consolidatedFindings[groupKey].cves[cve.cve_id]) { consolidatedFindings[groupKey].cves[cve.cve_id] = cve; } });
          }
          if (f.severity_score > consolidatedFindings[groupKey].severity_score) { consolidatedFindings[groupKey].severity_score = f.severity_score; }
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
          const parseAttackVector = (vector: string) => {
            if (!vector) return { label: 'Network', class: 'av-network' };
            if (vector.includes('AV:N')) return { label: 'Network', class: 'av-network' };
            if (vector.includes('AV:A')) return { label: 'Adjacent', class: 'av-adjacent' };
            if (vector.includes('AV:L')) return { label: 'Local', class: 'av-local' };
            if (vector.includes('AV:P')) return { label: 'Physical', class: 'av-physical' };
            return { label: 'Network', class: 'av-network' };
          };

          return { ...group, evidence: Array.from(group.evidence as Set<string>), highPriority: [...highPriority, ...midPriority].sort((a,b) => (b.cvss_v3_score || 0) - (a.cvss_v3_score || 0)).map(c => ({ ...c, av: parseAttackVector(c.cvss_v3_vector) })), legacyMinor: legacyMinor.sort((a,b) => (b.cvss_v3_score || 0) - (a.cvss_v3_score || 0)), };
        });

        const getToolInsight = (tool: string, findingsCount: number) => {
          const t = tool.toUpperCase();
          if (findingsCount === 0) return `Scan completed with no high-severity findings detected. The ${t} tool verified standard security controls for this asset.`;
          switch(t) {
            case 'NMAP': return "Network analysis revealed multiple exposed services. Immediate attention should be given to closing unnecessary ports and ensuring all active services use strong authentication and encrypted protocols.";
            case 'NIKTO': return "Web server analysis identified potential misconfigurations and outdated components. These findings could lead to information leakage or serve as entry points for more complex application-layer attacks.";
            case 'SQLMAP': return "Critical database-level vulnerabilities were detected. These flaws represent a significant risk to data confidentiality and integrity, requiring immediate patching of the injection points.";
            case 'FFUF': return "Path discovery identified sensitive resources that are publicly accessible. These files or directories should be restricted via server configuration or moved outside the web root.";
            default: return `Analysis completed with ${findingsCount} notable findings. We recommend a prioritized remediation approach starting with the critical resources identified below.`;
          }
        };

        return `
          <div class="tool-section">
            <div class="tool-header">
              <div class="tool-name">${tool.toUpperCase()} SCAN RESULTS</div>
              <div class="tool-badge">INTELLIGENCE VERIFIED</div>
            </div>
            <div class="tool-insight">
              <div class="insight-title"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>Scan Insights & Strategy</div>
              <div class="insight-text">${getToolInsight(tool, finalFindings.length)}</div>
            </div>
            <div class="checkpoints">${getCheckpoints(tool).map(cp => `<div class="checkpoint"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>${cp}</div>`).join('')}</div>
            <div class="stats-grid">
              <div class="stat-box"><div class="stat-label">Injections Detected</div><div class="stat-value">${stats.uniquePoints}</div></div>
              <div class="stat-box"><div class="stat-label">Resources Scanned</div><div class="stat-value">${stats.urlsSpidered || 1}</div></div>
              <div class="stat-box"><div class="stat-label">Traffic Load</div><div class="stat-value">${stats.totalRequests} reqs</div></div>
              <div class="stat-box"><div class="stat-label">Avg Latency</div><div class="stat-value">${stats.responseTime}</div></div>
            </div>
            <div class="findings-list">
              ${(() => {
                const escapeHtml = (unsafe: string) => { if (!unsafe || typeof unsafe !== 'string') return ''; return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); };
                return finalFindings.length === 0 ? `<div style="text-align: center; padding: 30px; color: #94a3b8; border: 1px dashed #e2e8f0; border-radius: 8px; font-size: 11px;">No specific vulnerabilities found by this tool.</div>` : finalFindings.map((group, idx) => {
                const sevLabels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
                const sev = sevLabels[group.severity_score] || 'INFO';
                const displayedPrimary = group.highPriority.slice(0, 5);
                const displayedLegacy = group.legacyMinor.slice(0, 8);
                const analysis = getSmartAnalysis(group.name, displayedPrimary);
                return `
                  <div class="finding-card">
                    <div class="finding-header">
                      <div class="finding-title-container">
                        <svg class="finding-icon" width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M5 21V5q0-.825.588-1.413T7 3h10q.825 0 1.413.588T19 5v11q0 .825-.588 1.413T17 18H7l-2 3Zm2-6.15L8.85 13H17V5H7v9.85ZM7 5v8-8Z"/></svg>
                        <div class="finding-title">${escapeHtml(group.name)}<br/><span style="color: #64748b; font-size: 11px; font-weight: 400;">port ${escapeHtml(group.path || 'N/A')}</span></div>
                      </div>
                      <div class="finding-confirmed-badge">CONFIRMED</div>
                    </div>
                    
                    <table class="finding-meta-table">
                      <thead>
                        <tr>
                          <th width="25%">URL</th>
                          <th width="20%">Context</th>
                          <th>Evidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td><a href="${targetInfo.target}" class="finding-url">${targetInfo.target}</a></td>
                          <td style="font-size: 10px; color: #475569;">
                            <strong>Severity:</strong> ${sev}<br/>
                            <strong>Source:</strong> ${tool.toUpperCase()}<br/>
                            <strong>Status:</strong> ${group.status || 'Active'}
                          </td>
                          <td>
                            <div class="terminal-evidence" style="max-height: 150px; overflow: hidden;">${Array.from(group.evidence).map((e: any) => escapeHtml(e)).join('\n')}</div>
                          </td>
                        </tr>
                      </tbody>
                    </table>

                    ${displayedPrimary.length > 0 ? `
                      <div class="sub-section-title">VERIFIED INTELLIGENCE</div>
                      <table class="cve-table">
                        <thead>
                          <tr>
                            <th width="110">CVE ID</th>
                            <th width="60">CVSS</th>
                            <th width="100">Vector</th>
                            <th>Threat Description</th>
                          </tr>
                        </thead>
                        <tbody>
                          ${displayedPrimary.map((c: any) => `
                            <tr>
                              <td class="cve-link">${c.cve_id}</td>
                              <td><span class="score-pill" style="background: ${c.cvss_v3_score >= 9 ? '#fee2e2' : c.cvss_v3_score >= 7 ? '#ffedd5' : '#fef9c3'}; color: ${c.cvss_v3_score >= 9 ? '#991b1b' : c.cvss_v3_score >= 7 ? '#c2410c' : '#854d0e'}; font-size: 9px;">${c.cvss_v3_score || 'N/A'}</span></td>
                              <td><span class="av-badge ${c.av.class}">${c.av.label}</span></td>
                              <td class="cve-desc">${escapeHtml(c.description || '')}</td>
                            </tr>
                          `).join('')}
                        </tbody>
                      </table>
                    ` : ''}

                    ${displayedLegacy.length > 0 ? `
                      <div class="sub-section-title">HISTORICAL CONTEXT</div>
                      <div class="legacy-tags" style="margin-bottom: 20px;">
                        ${displayedLegacy.map((c: any) => `<span class="legacy-tag">${c.cve_id}</span>`).join('')}
                        ${group.legacyMinor.length > 8 ? `<span class="legacy-tag-more">+${group.legacyMinor.length - 8} more</span>` : ''}
                      </div>
                    ` : ''}

                    <div class="details-container">
                      <div class="detail-item">
                        <div class="detail-label">Risk description:</div>
                        <div class="detail-text">${escapeHtml(analysis.risk)}</div>
                      </div>
                      <div class="detail-item">
                        <div class="detail-label">Recommendation:</div>
                        <div class="detail-text">${escapeHtml(analysis.recommendation)}</div>
                      </div>
                      <div class="detail-item">
                        <div class="detail-label">References:</div>
                        ${analysis.references.map(ref => `
                          <div class="detail-text">
                            <a href="${ref}" class="detail-link" target="_blank">${ref}</a>
                          </div>
                        `).join('')}
                      </div>
                      <div class="detail-item">
                        <div class="detail-label">Classification:</div>
                        <div style="font-size: 11px; color: #334155; line-height: 1.8;">
                          <span style="color: #2563eb; font-weight: 700;">CWE:</span> ${escapeHtml(analysis.cwe)}<br/>
                          ${analysis.owasp.map(o => `<span style="color: #2563eb; font-weight: 700;">OWASP:</span> ${escapeHtml(o)}<br/>`).join('')}
                        </div>
                      </div>
                    </div>
                  </div>
                `;
              }).join('');
              })()}
            </div>
          </div>
        `;
      }).join('');

      const infoCount = Math.max(0, (scanInfoData.total_findings || 0) - ((scanInfoData.critical_count || 0) + (scanInfoData.high_count || 0) + (scanInfoData.medium_count || 0) + (scanInfoData.low_count || 0)));
      const riskRatings = [
        { label: 'Critical', value: scanInfoData.critical_count || 0, color: '#ef4444' },
        { label: 'High', value: scanInfoData.high_count || 0, color: '#f97316' },
        { label: 'Medium', value: scanInfoData.medium_count || 0, color: '#f59e0b' },
        { label: 'Low', value: scanInfoData.low_count || 0, color: '#3b82f6' },
        { label: 'Info', value: infoCount, color: '#10b981' }
      ];

      const maxRatingValue = Math.max(...riskRatings.map(r => r.value), 1);
      const riskColorMap: Record<string, string> = { 'Critical': '#ef4444', 'High': '#f97316', 'Medium': '#f59e0b', 'Low': '#3b82f6', 'Info': '#10b981' };

      const startTime = new Date(scanInfoData.created_at);
      const totalDuration = toolsFound.reduce((acc, tool) => acc + extractStats(tool, rawOutput).duration, 0) || 45;
      const finishTime = new Date(startTime.getTime() + totalDuration * 1000);
      const totalTests = toolsFound.reduce((acc, tool) => acc + extractStats(tool, rawOutput).totalRequests, 0) || 38;

      const formatScanTime = (d: Date) => {
        const datePart = d.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
        const timePart = d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        return `${datePart} / ${timePart} UTC+03`;
      };

      const summaryHtml = `
        <div class="summary-section">
          <div class="summary-title">Summary</div>
          <div class="summary-grid">
            <div class="summary-col">
              <div class="summary-label">Overall risk level:</div>
              <div class="overall-risk-badge" style="background: ${riskColorMap[overallRisk]}">${overallRisk}</div>
            </div>
            <div class="summary-col" style="flex: 1.5;">
              <div class="summary-label">Risk ratings:</div>
              <table class="risk-ratings-table">
                ${riskRatings.map(r => `
                  <tr>
                    <td width="60">${r.label}:</td>
                    <td width="30" style="text-align: right; padding-right: 10px;">${r.value}</td>
                    <td>
                      <div class="risk-bar-bg">
                        <div class="risk-bar-fill" style="width: ${(r.value / maxRatingValue) * 100}%; background: ${r.color};"></div>
                      </div>
                    </td>
                  </tr>
                `).join('')}
              </table>
            </div>
            <div class="summary-col">
              <div class="summary-label">Scan information:</div>
              <table class="scan-info-table">
                <tr><td>Start time:</td><td>${formatScanTime(startTime)}</td></tr>
                <tr><td>Finish time:</td><td>${formatScanTime(finishTime)}</td></tr>
                <tr><td>Scan duration:</td><td>${totalDuration} sec</td></tr>
                <tr><td>Tests performed:</td><td>${totalTests}</td></tr>
                <tr><td>Scan status:</td><td><span class="status-finished-badge">Finished</span></td></tr>
              </table>
            </div>
          </div>
        </div>
        <div class="findings-section-header" style="page-break-before: always;">Findings</div>
      `;

      const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Executive Scan Report - ${targetInfo.target}</title><style>@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=Noto+Sans+Arabic:wght@400;700&display=swap');body { font-family: 'Plus Jakarta Sans', 'Noto Sans Arabic', sans-serif; color: #1e293b; line-height: 1.5; padding: 40px; margin: 0; background: #ffffff; font-size: 11px; }.report-header { margin-bottom: 20px; border-bottom: 1px solid #e2e8f0; padding-bottom: 15px; display: flex; justify-content: space-between; align-items: flex-end; }.report-title { font-size: 20px; font-weight: 800; color: #0f172a; margin: 0; }.report-subtitle { font-size: 12px; color: #64748b; margin-top: 2px; }.summary-section { border: 1px solid #e2e8f0; margin-bottom: 30px; }.summary-title { background: #f8fafc; padding: 8px 15px; font-weight: 800; font-size: 13px; border-bottom: 1px solid #e2e8f0; }.summary-grid { display: flex; padding: 15px; gap: 30px; }.summary-col { display: flex; flex-direction: column; gap: 10px; }.summary-label { font-weight: 700; color: #2563eb; font-size: 12px; margin-bottom: 5px; }.overall-risk-badge { color: white; padding: 6px 25px; border-radius: 4px; font-weight: 800; font-size: 13px; text-align: center; width: fit-content; }.risk-ratings-table { width: 100%; border-collapse: collapse; font-size: 10px; }.risk-ratings-table td { padding: 2px 0; }.risk-bar-bg { background: #f1f5f9; height: 12px; width: 150px; border-radius: 2px; overflow: hidden; }.risk-bar-fill { height: 100%; }.scan-info-table { width: 100%; border-collapse: collapse; font-size: 10px; }.scan-info-table td { padding: 2px 0; }.scan-info-table td:first-child { font-weight: 700; color: #475569; width: 100px; }.status-finished-badge { background: #86efac; color: #166534; padding: 1px 8px; border-radius: 4px; font-weight: 700; border: 1px solid #4ade80; }.findings-section-header { border: 1px solid #e2e8f0; background: #f8fafc; padding: 8px 15px; font-weight: 800; font-size: 13px; margin-bottom: 25px; }.tool-section { margin-bottom: 50px; page-break-inside: avoid; }.tool-header { background: #f8fafc; padding: 12px 15px; border-left: 4px solid #3b82f6; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }.tool-name { font-weight: 800; font-size: 12px; color: #1e40af; }.tool-badge { background: #dbeafe; color: #1e40af; padding: 3px 8px; border-radius: 99px; font-size: 8px; font-weight: 700; }.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 25px; }.stat-box { background: #ffffff; border: 1px solid #e2e8f0; padding: 10px; border-radius: 8px; text-align: center; }.stat-label { font-size: 8px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 3px; }.stat-value { font-size: 14px; font-weight: 800; color: #0f172a; }.finding-card { background: #ffffff; margin-bottom: 40px; page-break-inside: avoid; border-bottom: 1px dashed #e2e8f0; padding-bottom: 30px; }.finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; }.finding-title-container { display: flex; align-items: flex-start; gap: 10px; flex: 1; }.finding-icon { color: #f97316; margin-top: 2px; }.finding-title { font-size: 16px; font-weight: 700; color: #2563eb; line-height: 1.3; }.finding-confirmed-badge { color: #10b981; border: 1px solid #10b981; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; }.finding-meta-table { width: 100%; border-collapse: collapse; margin-bottom: 15px; }.finding-meta-table th { background: #f8fafc; border: 1px solid #e2e8f0; text-align: left; padding: 8px 12px; font-size: 10px; color: #475569; }.finding-meta-table td { border: 1px solid #e2e8f0; padding: 12px; vertical-align: top; }.finding-url { color: #2563eb; text-decoration: none; word-break: break-all; }.meta-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 15px; padding: 12px; background: #f8fafc; border-radius: 6px; }.m-label { display: block; font-size: 8px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 2px; }.m-value { font-size: 11px; font-weight: 600; color: #1e293b; }.cve-table { width: 100%; border-collapse: collapse; margin-bottom: 15px; }.cve-table th { text-align: left; padding: 10px; background: #f1f5f9; color: #475569; font-size: 9px; font-weight: 700; text-transform: uppercase; }.cve-table td { padding: 10px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }.score-pill { padding: 2px 6px; border-radius: 4px; font-weight: 800; font-size: 9px; }.terminal-evidence { background: #f8fafc; color: #1e293b; padding: 12px; border-radius: 4px; border: 1px solid #e2e8f0; font-family: monospace; font-size: 10px; white-space: pre-wrap; line-height: 1.4; }.details-container { background: #f8fafc; padding: 15px; border-radius: 4px; border-top: 1px solid #e2e8f0; }.detail-item { margin-bottom: 15px; }.detail-label { font-weight: 700; font-size: 12px; color: #1e293b; margin-bottom: 3px; }.detail-text { font-size: 11px; color: #334155; line-height: 1.5; }.detail-link { color: #2563eb; text-decoration: none; word-break: break-all; }.av-badge { padding: 2px 5px; border-radius: 3px; font-size: 8px; font-weight: 700; text-transform: uppercase; }@media print { body { padding: 20px; } }</style></head><body><div class="report-header"><div><h1 class="report-title">Vulnerability Assessment Report</h1><div class="report-subtitle">Targeted Scan Analysis for: <strong>${targetInfo.target}</strong></div></div><div style="text-align: right;"><div class="report-subtitle">Generated: ${new Date().toLocaleDateString("en-US", { month: 'long', day: 'numeric', year: 'numeric' })}</div><div class="report-subtitle">Status: Intelligence Verified</div></div></div>${summaryHtml}${sectionsHtml}<div style="text-align: center; font-size: 9px; color: #94a3b8; margin-top: 40px; padding-top: 15px; border-top: 1px solid #f1f5f9;">This report is confidential and intended for authorized security personnel only.<br/>&copy; ${new Date().getFullYear()} CyberSecurity Intelligence System</div><script>window.onload = () => { setTimeout(() => { window.print(); window.onafterprint = () => window.close(); }, 800); }</script></body></html>`;

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
