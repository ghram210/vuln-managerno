import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { AlertTriangle, MoreHorizontal } from "lucide-react";
import { cn } from "@/lib/utils";

const filterTags = [
  "Open vulnerabilities",
  "CISA KEV",
];

type SeverityKey = "Critical" | "High" | "Medium" | "Low" | "Info" | "None";

const severityStyles: Record<SeverityKey, { dot: string; text: string; hex: string }> = {
  Critical: { dot: "bg-severity-critical", text: "text-severity-critical", hex: "hsl(0 84% 60%)" },
  High: { dot: "bg-severity-high", text: "text-severity-high", hex: "hsl(24 95% 53%)" },
  Medium: { dot: "bg-severity-medium", text: "text-severity-medium", hex: "hsl(45 93% 47%)" },
  Low: { dot: "bg-severity-low", text: "text-severity-low", hex: "hsl(142 71% 45%)" },
  Info: { dot: "bg-severity-info", text: "text-severity-info", hex: "hsl(215 20% 65%)" },
  None: { dot: "bg-severity-none", text: "text-severity-none", hex: "hsl(215 15% 75%)" },
};

const fallbackStyle = { dot: "bg-muted-foreground", text: "text-muted-foreground" };

const exploitStyles: Record<string, { dot: string; text: string; bg: string }> = {
  "Actively Used": {
    dot: "bg-severity-critical",
    text: "text-severity-critical",
    bg: "bg-severity-critical/20",
  },
  Available: {
    dot: "bg-severity-high",
    text: "text-severity-high",
    bg: "bg-severity-high/15",
  },
  Unproven: {
    dot: "bg-severity-medium",
    text: "text-severity-medium",
    bg: "bg-severity-medium/15",
  },
  None: {
    dot: "bg-severity-none",
    text: "text-severity-none",
    bg: "bg-severity-none/15",
  },
};

const SeverityCell = ({ value }: { value: string | null | undefined }) => {
  if (!value) return <span className="text-muted-foreground text-[11px]">—</span>;
  const style = severityStyles[value as SeverityKey] ?? fallbackStyle;
  const color = "hex" in style ? style.hex : undefined;
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`w-2 h-2 rounded-full ${style.dot}`} style={color ? { backgroundColor: color } : {}} />
      <span className={`font-medium text-[11px] ${style.text}`} style={color ? { color } : {}}>{value}</span>
    </span>
  );
};

const ExploitCell = ({ value }: { value: string | null | undefined }) => {
  const v = value ?? "None";
  const style =
    exploitStyles[v] ??
    {
      dot: "bg-muted-foreground",
      text: "text-foreground",
      bg: "bg-secondary",
    };
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold ${style.bg} ${style.text}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
      {v}
    </span>
  );
};

const getSmartSummary = (text: string | null) => {
  if (!text) return "—";
  // Matches until the first period that is followed by a space or end of string.
  // This helps avoid splitting on "v1.2" etc.
  const match = text.match(/^[\s\S]*?\.(?:\s|$)/);
  return match ? match[0].trim() : text;
};

const VULN_TYPES = [
  "SQL Injection", "Cross-Site Scripting", "XSS", "Server-Side Request Forgery", "SSRF",
  "Remote Code Execution", "RCE", "Local File Inclusion", "LFI", "Remote File Inclusion", "RFI",
  "Path Traversal", "Insecure Deserialization", "Broken Authentication", "Broken Access Control",
  "Security Misconfiguration", "Cross-Site Request Forgery", "CSRF", "Open Redirect",
  "Clickjacking", "Buffer Overflow", "Command Injection", "Directory Listing",
  "Exposed Credentials", "Information Disclosure", "Insecure TLS", "Hardcoded Secrets",
  "Denial of Service", "DoS", "Privilege Escalation", "Cryptographic Failures",
  "Outdated Component", "Vulnerable Dependency", "Sensitive Data Exposure"
];

const getVulnerabilityName = (description: string | null, vulnerabilityName: string | null) => {
  // If we have a meaningful vulnerability_name from the database, use it.
  // But we still want to filter out technical fingerprints if the DB name is just that.

  if (vulnerabilityName) {
     const isFingerprint = /^[a-z0-9_-]+ [\d.]+ \([a-z]+\)$/i.test(vulnerabilityName);
     if (!isFingerprint && vulnerabilityName.length < 50) return vulnerabilityName;
  }

  if (!description) return vulnerabilityName || "Security Vulnerability";

  // Try to find a standard vulnerability type in the description
  for (const type of VULN_TYPES) {
    const regex = new RegExp(`\\b${type.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')}\\b`, 'i');
    if (regex.test(description)) return type;
  }

  // Fallback: Take the first few words of the description
  const words = description.split(/\s+/).slice(0, 4).join(" ");
  return words.length > 3 ? words.replace(/[^a-zA-Z\s]/g, "").trim() : (vulnerabilityName || "General Vulnerability");
};

const VulnerabilitiesTab = () => {
  const navigate = useNavigate();
  const [filterRating, setFilterRating] = useState("all");
  const [filterExploit, setFilterExploit] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [selectedTags, setSelectedTags] = useState<string[]>(["Open vulnerabilities"]);
  const [showRatingDrop, setShowRatingDrop] = useState(false);
  const [showExploitDrop, setShowExploitDrop] = useState(false);
  const [showStatusDrop, setShowStatusDrop] = useState(false);

  const toggleTag = (tag: string) => {
    setSelectedTags((prev) =>
      prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]
    );
  };

  const { data: vulnerabilities = [] } = useQuery({
    queryKey: ["vulnerabilities"],
    queryFn: async () => {
      const { data, error } = await supabase
        .from("vulnerabilities")
        .select("*")
        .order("created_at", { ascending: true });
      if (error) throw error;
      return data;
    },
  });

  const cveIds = useMemo(
    () =>
      Array.from(
        new Set(
          vulnerabilities
            .map((v) => v.cve_id)
            .filter((x): x is string => Boolean(x))
        )
      ),
    [vulnerabilities]
  );

  const { data: cveCatalog = [] } = useQuery({
    queryKey: ["cve_catalog_for_vulns", cveIds.length, cveIds.join(",")],
    enabled: cveIds.length > 0,
    queryFn: async () => {
      const { data, error } = await supabase
        .from("cve_catalog")
        .select("cve_id, cvss_v3_score, published_date")
        .in("cve_id", cveIds);
      if (error) throw error;
      return data ?? [];
    },
  });

  const cveMap = useMemo(() => {
    const m = new Map<string, { score: number | null; published: string | null }>();
    for (const c of cveCatalog) {
      m.set(c.cve_id, {
        score: c.cvss_v3_score ?? null,
        published: c.published_date ?? null,
      });
    }
    return m;
  }, [cveCatalog]);

  const filtered = vulnerabilities.filter((v) => {
    if (filterRating !== "all" && v.cvss_severity !== filterRating) return false;
    if (filterExploit !== "all" && v.exploit_status !== filterExploit) return false;
    if (filterStatus !== "all" && v.status !== filterStatus) return false;
    if (selectedTags.includes("Open vulnerabilities") && v.status !== "Open") return false;
    if (selectedTags.includes("CISA KEV") && v.exploit_status !== "Actively Used") return false;
    return true;
  });

  const ratingOptions = ["All Ratings", "Critical", "High", "Medium", "Low"];
  const exploitOptions = ["All Exploits", "Actively Used", "Available", "Unproven", "None"];
  const statusOptions = ["All Status", "Open", "In Progress", "Closed", "Suppressed"];

  const closeAllDrops = () => {
    setShowRatingDrop(false);
    setShowExploitDrop(false);
    setShowStatusDrop(false);
  };

  const DropdownFilter = ({
    label,
    value,
    options,
    show,
    setShow,
    setValue,
  }: {
    label: string;
    value: string;
    options: string[];
    show: boolean;
    setShow: (v: boolean) => void;
    setValue: (v: string) => void;
  }) => {
    const allLabel = options[0];
    return (
      <div className="relative">
        <button
          onClick={() => {
            closeAllDrops();
            setShow(!show);
          }}
          className="flex items-center gap-2 px-3 py-1 text-xs bg-secondary border border-border rounded-md"
        >
          {value === "all" ? allLabel : value}
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {show && (
          <div className="absolute z-10 mt-1 bg-card border border-border rounded-lg shadow-lg py-1 min-w-[140px]">
            {options.map((opt) => {
              const val = opt === allLabel ? "all" : opt;
              const active = value === val;
              return (
                <button
                  key={opt}
                  onClick={() => {
                    setValue(val);
                    setShow(false);
                  }}
                  className={cn(
                    "w-full text-left px-3 py-1 text-xs hover:bg-accent",
                    active ? "bg-primary text-primary-foreground" : ""
                  )}
                >
                  {opt}
                </button>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-3">
      {/* Filter row */}
      <div className="flex items-center gap-3">
        <span className="text-[11px] text-muted-foreground">Filter by:</span>
        <DropdownFilter
          label="Ratings"
          value={filterRating}
          options={ratingOptions}
          show={showRatingDrop}
          setShow={setShowRatingDrop}
          setValue={setFilterRating}
        />
        <DropdownFilter
          label="Exploits"
          value={filterExploit}
          options={exploitOptions}
          show={showExploitDrop}
          setShow={setShowExploitDrop}
          setValue={setFilterExploit}
        />
        <DropdownFilter
          label="Status"
          value={filterStatus}
          options={statusOptions}
          show={showStatusDrop}
          setShow={setShowStatusDrop}
          setValue={setFilterStatus}
        />
        <span className="ml-auto text-[11px] text-muted-foreground">{filtered.length.toLocaleString("en-US")} results</span>
      </div>

      {/* Info banner */}
      <div className="bg-card rounded-lg border border-border p-3">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 text-severity-high" />
            <span className="text-[11px] font-medium text-foreground">
              {filtered.length.toLocaleString("en-US")} vulnerabilities found
            </span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {filterTags.map((tag, i) => {
            const isActive = selectedTags.includes(tag);
            return (
              <button
                key={i}
                onClick={() => toggleTag(tag)}
                className={cn(
                  "text-[10px] px-2 py-0.5 rounded transition-colors",
                  isActive
                    ? "bg-primary/20 text-primary font-medium border border-primary/30"
                    : "text-muted-foreground hover:bg-secondary border border-transparent"
                )}
              >
                {tag}
              </button>
            );
          })}
          <button
            onClick={() => setSelectedTags([])}
            className="text-[10px] text-muted-foreground cursor-pointer hover:text-foreground ml-auto"
          >
            Clear all
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-card rounded-lg border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-secondary/30">
                <th className="text-left px-3 py-2 text-[11px] font-bold text-primary uppercase tracking-wider">CVE</th>
                <th className="text-left px-3 py-2 text-[11px] font-bold text-primary uppercase tracking-wider">Vulnerability Name</th>
                <th className="text-left px-3 py-2 text-[11px] font-bold text-primary uppercase tracking-wider">Exprt Rating</th>
                <th className="text-left px-3 py-2 text-[11px] font-bold text-primary uppercase tracking-wider">Severity</th>
                <th className="text-left px-3 py-2 text-[11px] font-bold text-primary uppercase tracking-wider">Description</th>
                <th className="text-left px-3 py-2 text-[11px] font-bold text-primary uppercase tracking-wider">Hits</th>
                <th className="text-left px-3 py-2 text-[11px] font-bold text-primary uppercase tracking-wider text-center">Exploit</th>
                <th className="text-left px-3 py-2 text-[11px] font-bold text-primary uppercase tracking-wider text-center">Score</th>
                <th className="text-left px-3 py-2 text-[11px] font-bold text-primary uppercase tracking-wider text-center w-10">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((v) => {
                const sev = (v.cvss_severity as SeverityKey) ?? "Info";
                const sevStyle = severityStyles[sev] ?? fallbackStyle;
                const dot = sevStyle.dot;
                const color = "hex" in sevStyle ? sevStyle.hex : undefined;
                const cveInfo = cveMap.get(v.cve_id);
                const score = cveInfo?.score;
                return (
                  <tr
                    key={v.id}
                    className="hover:bg-secondary/40 transition-colors cursor-pointer h-[40px]"
                    onClick={() => navigate(`/scan-results?scanId=${v.id}`)}
                  >
                    <td className="px-3 py-2 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${dot}`} style={color ? { backgroundColor: color } : {}} />
                        <span className="text-primary font-mono text-[11px] font-semibold">
                          {v.cve_id ?? "—"}
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <span className="text-foreground/90 font-semibold text-[11px] block truncate max-w-[200px]">
                        {getVulnerabilityName(v.description, v.vulnerability_name)}
                      </span>
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <SeverityCell value={v.exprt_rating} />
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <SeverityCell value={v.cvss_severity} />
                    </td>
                    <td className="px-3 py-2 text-foreground/80 max-w-[400px]">
                      <span className="text-[11px] leading-relaxed block truncate" title={v.description ?? ""}>
                        {getSmartSummary(v.description)}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-foreground/90 text-center font-bold text-[11px] tabular-nums">
                      {(v.vulnerability_count ?? 0).toLocaleString("en-US")}
                    </td>
                    <td className="px-3 py-2 text-center whitespace-nowrap">
                      <ExploitCell value={v.exploit_status} />
                    </td>
                    <td className="px-3 py-2 text-center">
                      {score !== undefined && score !== null ? (
                        <span
                          className={`inline-flex items-center justify-center min-w-[36px] px-1.5 py-0.5 rounded text-[10px] font-bold tabular-nums bg-secondary border border-border ${severityStyles[sev]?.text}`}
                          style={color ? { color } : {}}
                        >
                          {Number(score).toFixed(1)}
                        </span>
                      ) : (
                        <span className="text-muted-foreground text-[10px]">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-center">
                      <button
                        className="text-muted-foreground hover:text-foreground p-1 transition-colors"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/scan-results?scanId=${v.id}`);
                        }}
                      >
                        <MoreHorizontal className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-3 py-12 text-center text-[11px] text-muted-foreground">
                    <div className="flex flex-col items-center gap-2">
                      <AlertTriangle className="w-6 h-6 opacity-20" />
                      No vulnerabilities match the current filters.
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default VulnerabilitiesTab;
