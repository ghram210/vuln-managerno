import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import type { DonutSegment } from "@/components/DonutChart";

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "hsl(0 85% 52%)",
  HIGH:     "hsl(22 90% 54%)",
  MEDIUM:   "hsl(40 92% 52%)",
  LOW:      "hsl(160 65% 46%)",
  NONE:     "hsl(220 18% 62%)",
  UNKNOWN:  "hsl(250 18% 58%)",
};
const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, NONE: 5, UNKNOWN: 6,
};

// Fallback: bucket by CVSS v3 numeric score when severity text is missing/uniform
function scoreBucket(score: number | null): { name: string; color: string; order: number } {
  if (score === null || score === undefined) return { name: "NONE",     color: SEVERITY_COLOR.NONE,     order: 5 };
  if (score >= 9.0)                         return { name: "CRITICAL", color: SEVERITY_COLOR.CRITICAL, order: 1 };
  if (score >= 7.0)                         return { name: "HIGH",     color: SEVERITY_COLOR.HIGH,     order: 2 };
  if (score >= 4.0)                         return { name: "MEDIUM",   color: SEVERITY_COLOR.MEDIUM,   order: 3 };
  if (score > 0)                            return { name: "LOW",      color: SEVERITY_COLOR.LOW,      order: 4 };
  return                                           { name: "NONE",     color: SEVERITY_COLOR.NONE,     order: 5 };
}

export function useCveCatalogChart() {
  return useQuery<DonutSegment[]>({
    queryKey: ["cve_catalog_severity"],
    queryFn: async () => {
      // Fetch severity + score for all CVEs in the catalog
      const { data, error } = await (supabase as any)
        .from("cve_catalog")
        .select("cvss_v3_severity, cvss_v3_score");

      if (error) {
        if (
          error.code === "42P01" ||
          /relation .* does not exist/i.test(error.message ?? "")
        ) {
          return [];
        }
        throw error;
      }

      if (!data?.length) return [];

      // Group by severity text first
      const bySev: Record<string, number> = {};
      for (const row of data) {
        const sev = (row.cvss_v3_severity ?? "UNKNOWN").toUpperCase().trim();
        bySev[sev] = (bySev[sev] ?? 0) + 1;
      }

      const keys = Object.keys(bySev);
      const onlyOneBucket = keys.length === 1;

      // If ALL CVEs are in one severity bucket, fall back to score-range bucketing
      // so the chart always shows a meaningful multi-segment distribution
      if (onlyOneBucket) {
        const byScore: Record<string, { color: string; order: number; count: number }> = {};
        for (const row of data) {
          const b = scoreBucket(row.cvss_v3_score);
          if (!byScore[b.name]) byScore[b.name] = { color: b.color, order: b.order, count: 0 };
          byScore[b.name].count += 1;
        }
        return Object.entries(byScore)
          .map(([name, { color, order, count }]) => ({ name, value: count, color, _order: order }))
          .sort((a, b) => a._order - b._order)
          .map(({ name, value, color }) => ({ name, value, color }));
      }

      // Normal case: multiple severity labels
      return Object.entries(bySev)
        .map(([sev, count]) => ({
          name: sev,
          value: count,
          color: SEVERITY_COLOR[sev] ?? SEVERITY_COLOR.UNKNOWN,
          _order: SEVERITY_ORDER[sev] ?? 99,
        }))
        .sort((a, b) => (a as any)._order - (b as any)._order)
        .map(({ name, value, color }) => ({ name, value, color }));
    },
    staleTime: 60_000,
  });
}
