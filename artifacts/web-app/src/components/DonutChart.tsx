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
  accentColor?: string;
}

const fmt = (n: number) =>
  n >= 1_000_000
    ? `${(n / 1_000_000).toFixed(1)}M`
    : n >= 1_000
    ? `${(n / 1_000).toFixed(1)}k`
    : n.toLocaleString("en-US");

const ActiveShape = (props: any) => {
  const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props;
  return (
    <g>
      <Sector
        cx={cx} cy={cy}
        innerRadius={innerRadius}
        outerRadius={outerRadius + 7}
        startAngle={startAngle}
        endAngle={endAngle}
        fill={fill}
        style={{ filter: `drop-shadow(0 0 10px ${fill}88)` }}
      />
    </g>
  );
};

const ChartTooltip = ({ active, payload, total }: any) => {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  const color = p.payload.color as string;
  const value = p.value as number;
  const pct = total > 0 ? ((value / total) * 100).toFixed(1) : "0.0";
  return (
    <div className="rounded-lg border border-border/80 bg-popover/95 backdrop-blur px-3 py-2 shadow-xl shadow-black/40">
      <div className="flex items-center gap-2">
        <span
          className="w-2.5 h-2.5 rounded-full shrink-0"
          style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }}
        />
        <span className="text-sm font-medium text-foreground">{p.payload.name}</span>
      </div>
      <div className="mt-1 flex items-baseline gap-2 pl-[18px]">
        <span className="text-base font-semibold tabular-nums" style={{ color }}>
          {fmt(value)}
        </span>
        <span className="text-xs text-muted-foreground tabular-nums">{pct}%</span>
      </div>
    </div>
  );
};

const DonutChart = ({
  title,
  subtitle,
  data,
  centerLabel = "Total",
  loading,
  emptyHint = "No scan data yet.",
  accentColor,
}: DonutChartProps) => {
  const [activeIdx, setActiveIdx] = useState<number | undefined>(undefined);
  const reactId = useId();
  const safeId = reactId.replace(/[^a-zA-Z0-9_-]/g, "");

  const total = useMemo(() => data.reduce((s, d) => s + (d.value || 0), 0), [data]);
  const allZero = !loading && total === 0;
  const primaryColor = accentColor ?? data[0]?.color ?? "hsl(var(--primary))";
  const activeColor = activeIdx !== undefined ? data[activeIdx]?.color : undefined;

  const gradId = (i: number) => `dg-${safeId}-${i}`;

  const displayData = useMemo(() => {
    if (allZero) {
      return data.map((d) => ({ ...d, value: 1, _phantom: true }));
    }
    return data;
  }, [data, allZero]);

  return (
    <div
      className="group relative bg-card rounded-xl border border-border/70 p-5 overflow-hidden transition-all duration-200
                 hover:border-[var(--chart-accent,hsl(var(--primary)))/40] hover:shadow-[0_0_32px_-10px_var(--chart-accent,hsl(var(--primary)/0.35))]"
      style={{ "--chart-accent": primaryColor } as React.CSSProperties}
    >
      <div
        className="pointer-events-none absolute -top-14 -right-14 w-44 h-44 rounded-full blur-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{ backgroundColor: `${primaryColor}18` }}
      />

      <div className="flex items-start justify-between mb-0.5 relative z-10">
        <h3 className="text-[14.5px] font-semibold text-foreground tracking-tight leading-tight">
          {title}
        </h3>
        {!allZero && !loading && (
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground/60 font-medium pt-0.5">
            {data.length} {data.length === 1 ? "category" : "categories"}
          </span>
        )}
      </div>
      {subtitle && (
        <p className="text-[12px] text-muted-foreground/80 leading-snug mb-3 relative z-10">
          {subtitle}
        </p>
      )}

      <div className="relative h-[186px] flex items-center justify-center">
        {loading ? (
          <div className="flex flex-col items-center gap-3">
            <div
              className="w-24 h-24 rounded-full border-[10px] border-border/40 border-t-[var(--chart-accent)] animate-spin"
              style={{ "--chart-accent": primaryColor } as React.CSSProperties}
            />
            <p className="text-[11px] text-muted-foreground animate-pulse">Loading…</p>
          </div>
        ) : (
          <>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <defs>
                  {displayData.map((d, i) => (
                    <linearGradient key={i} id={gradId(i)} x1="0" y1="0" x2="1" y2="1">
                      <stop offset="0%" stopColor={d.color} stopOpacity={allZero ? 0.15 : 1} />
                      <stop offset="100%" stopColor={d.color} stopOpacity={allZero ? 0.08 : 0.82} />
                    </linearGradient>
                  ))}
                </defs>
                {!allZero && (
                  <Tooltip
                    content={<ChartTooltip total={total} />}
                    cursor={false}
                    wrapperStyle={{ outline: "none" }}
                  />
                )}
                <Pie
                  data={displayData}
                  cx="50%" cy="50%"
                  innerRadius={56} outerRadius={80}
                  paddingAngle={allZero ? 0 : (displayData.filter(d => d.value > 0).length > 1 ? 2 : 0)}
                  cornerRadius={allZero ? 0 : (displayData.filter(d => d.value > 0).length > 1 ? 5 : 0)}
                  dataKey="value"
                  stroke="hsl(var(--card))"
                  strokeWidth={allZero ? 0 : 2}
                  activeIndex={allZero ? undefined : activeIdx}
                  activeShape={allZero ? undefined : ActiveShape}
                  onMouseEnter={allZero ? undefined : (_, i) => setActiveIdx(i)}
                  onMouseLeave={allZero ? undefined : () => setActiveIdx(undefined)}
                  isAnimationActive={!allZero}
                  animationDuration={700}
                  animationEasing="ease-out"
                >
                  {displayData.map((_, i) => (
                    <Cell key={i} fill={`url(#${gradId(i)})`} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>

            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              {allZero ? (
                <>
                  <span className="text-[22px] font-bold tabular-nums text-muted-foreground/40">0</span>
                  <span className="text-[9.5px] uppercase tracking-[0.18em] text-muted-foreground/35 mt-1">
                    {centerLabel}
                  </span>
                </>
              ) : (
                <>
                  <span
                    className="text-[26px] font-bold tracking-tight leading-none transition-colors duration-150"
                    style={{ color: activeColor ?? "hsl(var(--foreground))" }}
                  >
                    {fmt(total)}
                  </span>
                  <span className="text-[9.5px] uppercase tracking-[0.18em] text-muted-foreground mt-1.5">
                    {centerLabel}
                  </span>
                </>
              )}
            </div>
          </>
        )}
      </div>

      <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-0.5">
        {data.map((d, i) => {
          const pct = total > 0 ? (d.value / total) * 100 : 0;
          const isActive = activeIdx === i;
          const isZero = d.value === 0;
          return (
            <button
              key={i}
              type="button"
              onMouseEnter={() => !allZero && !isZero && setActiveIdx(i)}
              onMouseLeave={() => setActiveIdx(undefined)}
              className={`flex items-center justify-between gap-1.5 rounded-md px-2 py-[5px] text-[11.5px] transition-colors
                ${isActive ? "bg-secondary/60" : "hover:bg-secondary/35"}
                ${isZero ? "opacity-45 cursor-default" : "cursor-default"}`}
            >
              <span className="flex items-center gap-1.5 min-w-0">
                <span
                  className="w-2 h-2 rounded-full shrink-0"
                  style={{
                    backgroundColor: d.color,
                    boxShadow: isActive
                      ? `0 0 8px ${d.color}`
                      : isZero
                      ? "none"
                      : `0 0 0 1px ${d.color}44`,
                  }}
                />
                <span
                  className="truncate font-medium"
                  style={{ color: isActive ? d.color : undefined }}
                >
                  {d.name}
                </span>
              </span>
              <span className="flex items-baseline gap-1 shrink-0 tabular-nums">
                <span className={`font-semibold ${isZero ? "text-muted-foreground/50" : "text-foreground"}`}>
                  {fmt(d.value)}
                </span>
                {!allZero && (
                  <span className="text-[10px] text-muted-foreground/60">
                    {pct.toFixed(0)}%
                  </span>
                )}
              </span>
            </button>
          );
        })}
      </div>

      {allZero && (
        <p className="text-[11px] text-muted-foreground/50 text-center mt-2 leading-relaxed px-2">
          {emptyHint}
        </p>
      )}
    </div>
  );
};

export default DonutChart;
