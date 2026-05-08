import { useState, useRef, useEffect } from "react";
import { ChevronDown, Globe, Check } from "lucide-react";
import DonutChart from "@/components/DonutChart";
import {
  useChartSeverity,
  useChartByTool,
  useChartExposure,
  useChartExploitability,
  useChartAttackVector,
  useChartStatus,
  useScanTargets,
} from "@/hooks/useAssetCharts";

// ─── URL middle-truncation ────────────────────────────────────────────────────
// Shows the START and END of a long URL with "…" in the middle.
// e.g. "https://0a170028.web-security-academy.net/filter?category=Gifts"
//   →  "0a170028.web-security-academy.net/fil…?category=Gifts"
function midTruncate(raw: string, maxLen = 52): string {
  const s = raw.replace(/^https?:\/\//, "");
  if (s.length <= maxLen) return s;
  const head = Math.round(maxLen * 0.58);
  const tail = Math.round(maxLen * 0.36);
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

// ─── Target Filter Dropdown ───────────────────────────────────────────────────

function TargetFilter({
  selected,
  onChange,
}: {
  selected: string | null;
  onChange: (v: string | null) => void;
}) {
  const { data: targets, isLoading } = useScanTargets();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handle(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, []);

  const selectedTarget = targets?.find((t) => t.url === selected);
  const displayLabel   = selected ? midTruncate(selected) : "All Targets";

  return (
    <div ref={ref} className="relative w-full max-w-[560px]">

      {/* ── Trigger button ── */}
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-2.5 rounded-xl border border-cyan-500/30 bg-cyan-500/6
                   px-4 py-2.5 transition-all duration-150
                   hover:border-cyan-400/55 hover:bg-cyan-500/10
                   focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
        style={{ boxShadow: open ? "0 0 20px -6px rgba(0,210,255,0.25)" : undefined }}
      >
        <Globe className="w-4 h-4 text-cyan-400 shrink-0" />

        {/* Middle-truncated URL — both start and end always visible */}
        <span className="flex-1 text-left text-[13px] font-semibold text-cyan-300 font-mono min-w-0">
          {isLoading ? "Loading…" : displayLabel}
        </span>

        {/* Findings / count badge */}
        {selectedTarget ? (
          <span className="text-[11px] font-medium text-cyan-500/70 tabular-nums shrink-0 ml-1">
            {selectedTarget.totalFindings.toLocaleString()} findings
          </span>
        ) : !isLoading && (targets?.length ?? 0) > 0 ? (
          <span className="text-[11px] font-medium text-cyan-500/70 tabular-nums shrink-0 ml-1">
            {targets!.length} targets
          </span>
        ) : null}

        <ChevronDown
          className={`w-4 h-4 text-cyan-400/70 shrink-0 transition-transform duration-200 ${
            open ? "rotate-180" : ""
          }`}
        />
      </button>

      {/* ── Dropdown ── */}
      {open && (
        <div
          className="absolute left-0 top-[calc(100%+6px)] z-50 w-full min-w-[380px]
                     rounded-xl border border-cyan-500/25 bg-card/95 backdrop-blur-md
                     shadow-2xl overflow-hidden"
          style={{ boxShadow: "0 8px 40px -8px rgba(0,0,0,0.7), 0 0 0 1px rgba(0,210,255,0.1)" }}
        >
          {/* "All Targets" row */}
          <button
            type="button"
            onClick={() => { onChange(null); setOpen(false); }}
            className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors
                        border-b border-border/40
                        ${!selected ? "bg-cyan-500/10" : "hover:bg-secondary/50"}`}
          >
            <div
              className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0
                          ${!selected ? "bg-cyan-500/20" : "bg-secondary/60"}`}
            >
              <Globe className={`w-3.5 h-3.5 ${!selected ? "text-cyan-400" : "text-muted-foreground"}`} />
            </div>
            <div className="flex-1 min-w-0">
              <div className={`text-[13px] font-semibold ${!selected ? "text-cyan-300" : "text-foreground"}`}>
                All Targets
              </div>
              <div className="text-[11px] text-muted-foreground/70">
                {isLoading ? "…" : `${targets?.length ?? 0} unique targets`}
              </div>
            </div>
            {!selected && <Check className="w-4 h-4 text-cyan-400 shrink-0" />}
          </button>

          {/* Target list */}
          <div className="max-h-72 overflow-y-auto">
            {isLoading ? (
              <div className="px-4 py-6 text-center text-[12px] text-muted-foreground/60">
                Loading targets…
              </div>
            ) : !targets?.length ? (
              <div className="px-4 py-6 text-center text-[12px] text-muted-foreground/60">
                No scan targets found
              </div>
            ) : (
              targets.map((t) => {
                const isSelected = selected === t.url;
                const isHttps    = t.url.startsWith("https://");
                const stripped   = t.url.replace(/^https?:\/\//, "");

                return (
                  <button
                    key={t.url}
                    type="button"
                    onClick={() => { onChange(t.url); setOpen(false); }}
                    className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors
                                border-b border-border/20 last:border-0
                                ${isSelected ? "bg-cyan-500/10" : "hover:bg-secondary/40"}`}
                  >
                    {/* Protocol badge */}
                    <div
                      className={`w-9 h-7 rounded-lg flex items-center justify-center shrink-0
                                  text-[8.5px] font-bold
                                  ${isHttps
                                    ? "bg-emerald-500/15 text-emerald-400"
                                    : "bg-amber-500/15 text-amber-400"}`}
                    >
                      {isHttps ? "HTTPS" : "HTTP"}
                    </div>

                    {/* URL — full string, no clipping, horizontal scroll if needed */}
                    <div className="flex-1 min-w-0">
                      <div
                        className={`text-[12px] font-mono font-semibold whitespace-nowrap overflow-x-auto
                                    scrollbar-none
                                    ${isSelected ? "text-cyan-300" : "text-foreground/90"}`}
                        title={t.url}
                      >
                        {stripped}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[10px] text-muted-foreground/60">
                          {t.scanCount} {t.scanCount === 1 ? "tool" : "tools"}
                        </span>
                        {t.totalFindings > 0 && (
                          <>
                            <span className="text-muted-foreground/30">·</span>
                            <span className="text-[10px] text-cyan-500/80 font-medium">
                              {t.totalFindings.toLocaleString()} findings
                            </span>
                          </>
                        )}
                      </div>
                    </div>

                    {isSelected && <Check className="w-4 h-4 text-cyan-400 shrink-0" />}
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

const DashboardDonuts = () => {
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);

  // All 6 hooks now accept the same target — bottom 3 are fully target-aware
  const severity       = useChartSeverity(selectedTarget);
  const byTool         = useChartByTool(selectedTarget);
  const exposure       = useChartExposure(selectedTarget);
  const exploitability = useChartExploitability(selectedTarget);
  const attackVector   = useChartAttackVector(selectedTarget);
  const status         = useChartStatus(selectedTarget);

  const selectedLabel = selectedTarget ? midTruncate(selectedTarget, 60) : null;

  return (
    <div className="space-y-4">

      {/* ── Header ── */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-foreground">Risk Overview</h2>
          <span className="text-[11px] text-muted-foreground/50 shrink-0">
            {selectedLabel ? `Showing: ${selectedLabel}` : "All scanned targets"}
          </span>
        </div>

        {/* Filter — always left-anchored, never wraps */}
        <TargetFilter selected={selectedTarget} onChange={setSelectedTarget} />
      </div>

      {/* ── 6 donut charts (all now respond to the target filter) ── */}
      <div className="grid grid-cols-3 gap-4">

        <DonutChart
          title="Finding Severity"
          subtitle="Findings classified by CVSS severity level"
          centerLabel="Findings"
          emptyHint="No findings for this target. Try running a scan."
          accentColor="hsl(0 84% 55%)"
          data={severity.data ?? []}
          loading={severity.isLoading}
        />
        <DonutChart
          title="Findings by Tool"
          subtitle="Findings per scanning tool (deduplicated)"
          centerLabel="Findings"
          emptyHint="No findings yet. Run FFUF, SQLMap, Nmap or Nikto."
          accentColor="hsl(243 72% 68%)"
          data={byTool.data ?? []}
          loading={byTool.isLoading}
        />
        <DonutChart
          title="Asset Exposure"
          subtitle="Scanned targets classified by type"
          centerLabel="Assets"
          emptyHint="No targets scanned yet."
          accentColor="hsl(315 95% 52%)"
          data={exposure.data ?? []}
          loading={exposure.isLoading}
        />

        <DonutChart
          title="Exploitability Risk"
          subtitle="CVEs classified by exploit availability"
          centerLabel="CVEs"
          emptyHint="No CVE data linked to your scans yet."
          accentColor="hsl(120 75% 38%)"
          data={exploitability.data ?? []}
          loading={exploitability.isLoading}
        />
        <DonutChart
          title="Attack Vector"
          subtitle="Network path for detected CVEs"
          centerLabel="CVEs"
          emptyHint="No CVSS data linked to your scans yet."
          accentColor="hsl(185 95% 40%)"
          data={attackVector.data ?? []}
          loading={attackVector.isLoading}
        />
        <DonutChart
          title="Finding Status"
          subtitle="Remediation state of detected CVEs"
          centerLabel="CVEs"
          emptyHint="No findings to track yet."
          accentColor="hsl(0 82% 55%)"
          data={status.data ?? []}
          loading={status.isLoading}
        />

      </div>
    </div>
  );
};

export default DashboardDonuts;
