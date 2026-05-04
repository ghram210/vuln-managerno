import { useId, useMemo, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Sector,
  Tooltip,
} from "recharts";

export interface DonutSegment {
  name: string;
  value: number;
  color: string;
}

interface DonutChartProps {
  title: string;
  subtitle?: string;
  data: DonutSegment[];
  centerLabel?: string;
  loading?: boolean;
  emptyHint?: string;
}

const formatValue = (n: number) =>
  n >= 1_000_000
    ? `${(n / 1_000_000).toFixed(1)}M`
    : n >= 1_000
    ? `${(n / 1_000).toFixed(1)}k`
    : n.toLocaleString("en-US");

const renderActiveShape = (props: any) => {
  const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props;
  return (
    <g>
      <Sector
        cx={cx}
        cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius + 6}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
        style={{ filter: `drop-shadow(0 0 12px ${fill})` }}
      />
    </g>
  );
};

const CustomTooltip = ({ active, payload, total }: any) => {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  const color = p.payload.color as string;
  const value = p.value as number;
  const pct = total > 0 ? ((value / total) * 100).toFixed(1) : "0";
  return (
    <div className="rounded-lg border border-border/80 bg-popover/95 backdrop-blur px-3 py-2 shadow-lg shadow-black/40">
      <div className="flex items-center gap-2">
        <span
          className="w-2.5 h-2.5 rounded-full shrink-0"
          style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }}
        />
        <span className="text-sm font-medium text-foreground">
          {p.payload.name}
        </span>
      </div>
      <div className="mt-1 flex items-baseline gap-2 pl-[18px]">
        <span className="text-base font-semibold tabular-nums" style={{ color }}>
          {formatValue(value)}
        </span>
        <span className="text-xs text-muted-foreground tabular-nums">
          {pct}%
        </span>
      </div>
    </div>
  );
};

const colorOverrides: Record<string, string> = {
  // Severity / Ratings
  Critical:   "hsl(0 84% 60%)",
  High:       "hsl(24 95% 53%)",
  Medium:     "hsl(45 93% 47%)",
  Low:        "hsl(142 71% 45%)",
  Info:       "hsl(215 20% 65%)",
  CRITICAL:   "hsl(0 84% 60%)",
  HIGH:       "hsl(24 95% 53%)",
  MEDIUM:     "hsl(45 93% 47%)",
  LOW:        "hsl(142 71% 45%)",
  NONE:       "hsl(215 20% 65%)",
  UNKNOWN:    "hsl(250 18% 58%)",

  // Exploitability Risk
  "Weaponized":  "hsl(0 84% 58%)",
  "Public PoC":  "hsl(24 95% 55%)",
  "Known CVE":   "hsl(45 90% 50%)",
  "Theoretical": "hsl(215 20% 65%)",

  // Findings type
  Vuln:    "hsl(0 84% 60%)",
  Misconf: "hsl(275 70% 60%)",

  // Attack Vector — vivid green palette
  Network:  "hsl(142 85% 42%)",
  Adjacent: "hsl(160 78% 48%)",
  Local:    "hsl(120 65% 52%)",
  Physical: "hsl(90 55% 58%)",

  // Asset Exposure — vivid pink/magenta palette
  "Web Application": "hsl(315 95% 52%)",
  "External Host":   "hsl(335 88% 58%)",
  "Internal Host":   "hsl(350 78% 65%)",
  "Network Service": "hsl(300 70% 60%)",
};

const DonutChart = ({
  title,
  subtitle,
  data: rawData,
  centerLabel = "Total",
  loading,
  emptyHint = "No data yet — run a scan to populate this chart.",
}: DonutChartProps) => {
  const data = useMemo(
    () =>
      rawData.map((d) => ({
        ...d,
        color: colorOverrides[d.name] || d.color,
      })),
    [rawData],
  );

  const [activeIndex, setActiveIndex] = useState<number | undefined>(undefined);
  const reactId = useId();
  const safeId = reactId.replace(/[^a-zA-Z0-9_-]/g, "");

  const total = useMemo(
    () => data.reduce((s, d) => s + (d.value || 0), 0),
    [data],
  );

  const isEmpty = !loading && data.length === 0;
  const isZeroTotal = !loading && !isEmpty && total === 0;

  const activeColor =
    activeIndex !== undefined ? data[activeIndex]?.color : undefined;

  const gradId = (i: number) => `donutgrad-${safeId}-${i}`;

  return (
    <div className="group relative bg-card rounded-xl border border-border/80 p-5 overflow-hidden transition-all hover:border-primary/40 hover:shadow-[0_0_28px_-12px_hsl(var(--primary)/0.45)]">
      <div className="pointer-events-none absolute -top-16 -right-16 w-48 h-48 rounded-full bg-primary/10 blur-3xl opacity-0 group-hover:opacity-100 transition-opacity" />

      {/* Header */}
      <div className="flex items-start justify-between mb-1 relative z-10">
        <h3 className="text-[15px] font-semibold text-foreground tracking-tight leading-tight">
          {title}
        </h3>
        {!isEmpty && !loading && (
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground/70 font-medium pt-1">
            {data.length} {data.length === 1 ? "category" : "categories"}
          </span>
        )}
      </div>
      {subtitle && (
        <p className="text-[12.5px] text-muted-foreground/90 leading-snug mb-3 relative z-10">
          {subtitle}
        </p>
      )}

      <div className="relative h-[190px] flex items-center justify-center">
        {loading ? (
          <div className="text-xs text-muted-foreground animate-pulse">
            Loading chart…
          </div>
        ) : isEmpty ? (
          <div className="flex flex-col items-center gap-2 text-center px-6">
            <div className="w-24 h-24 rounded-full border-[10px] border-border/60" />
            <p className="text-xs text-muted-foreground max-w-[240px] leading-relaxed">
              {emptyHint}
            </p>
          </div>
        ) : (
          <>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <defs>
                  {data.map((d, i) => (
                    <linearGradient
                      key={i}
                      id={gradId(i)}
                      x1="0"
                      y1="0"
                      x2="1"
                      y2="1"
                    >
                      <stop offset="0%" stopColor={d.color} stopOpacity={1} />
                      <stop
                        offset="100%"
                        stopColor={d.color}
                        stopOpacity={0.85}
                      />
                    </linearGradient>
                  ))}
                </defs>
                <Tooltip
                  content={<CustomTooltip total={total} />}
                  cursor={false}
                  wrapperStyle={{ outline: "none" }}
                  active={!isZeroTotal}
                />
                <Pie
                  data={isZeroTotal ? [{ name: "No data", value: 1, color: "hsl(var(--muted-foreground)/0.2)" }] : data}
                  cx="50%"
                  cy="50%"
                  innerRadius={58}
                  outerRadius={82}
                  paddingAngle={!isZeroTotal && data.length > 1 ? 2 : 0}
                  cornerRadius={!isZeroTotal && data.length > 1 ? 6 : 0}
                  dataKey="value"
                  stroke="hsl(var(--card))"
                  strokeWidth={!isZeroTotal && data.length > 1 ? 2 : 0}
                  activeIndex={isZeroTotal ? undefined : activeIndex}
                  activeShape={isZeroTotal ? undefined : renderActiveShape}
                  onMouseEnter={isZeroTotal ? undefined : (_, i) => setActiveIndex(i)}
                  onMouseLeave={isZeroTotal ? undefined : () => setActiveIndex(undefined)}
                  isAnimationActive
                  animationDuration={650}
                  animationEasing="ease-out"
                >
                  {isZeroTotal ? (
                    <Cell fill="hsl(var(--muted-foreground)/0.1)" stroke="none" />
                  ) : (
                    data.map((d, i) => (
                      <Cell key={i} fill={`url(#${gradId(i)})`} />
                    ))
                  )}
                </Pie>
              </PieChart>
            </ResponsiveContainer>

            {/* Center — always shows the grand total, color shifts on hover */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span
                className="text-[26px] font-bold tracking-tight leading-none transition-colors duration-150"
                style={{ color: activeColor ?? "hsl(var(--foreground))" }}
              >
                {formatValue(total)}
              </span>
              <span className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground mt-1.5">
                {centerLabel}
              </span>
            </div>
          </>
        )}
      </div>

      {/* Legend — always at bottom, outside the donut */}
      {!isEmpty && !loading && (
        <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1">
          {data.map((d, i) => {
            const pct = total > 0 ? (d.value / total) * 100 : 0;
            const isActive = activeIndex === i;
            return (
              <button
                key={i}
                type="button"
                onMouseEnter={() => setActiveIndex(i)}
                onMouseLeave={() => setActiveIndex(undefined)}
                className={`flex items-center justify-between gap-2 rounded-md px-2 py-1 text-[12px] transition-colors ${
                  isActive ? "bg-secondary/60" : "hover:bg-secondary/40"
                }`}
              >
                <span className="flex items-center gap-1.5 min-w-0">
                  <span
                    className="w-2 h-2 rounded-full shrink-0 transition-shadow"
                    style={{
                      backgroundColor: d.color,
                      boxShadow: isActive
                        ? `0 0 8px ${d.color}`
                        : `0 0 0 1px ${d.color}33`,
                    }}
                  />
                  <span
                    className="truncate font-medium"
                    style={{ color: isActive ? d.color : undefined }}
                  >
                    {d.name}
                  </span>
                </span>
                <span className="flex items-baseline gap-1 shrink-0">
                  <span className="text-foreground font-semibold tabular-nums">
                    {formatValue(d.value)}
                  </span>
                  <span className="text-[10px] text-muted-foreground tabular-nums">
                    {pct.toFixed(0)}%
                  </span>
                </span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default DonutChart;
