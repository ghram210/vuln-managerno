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
    queryKey: ["cve_catalog_severity_global"],
    queryFn: async () => {
      // Restore Global context for the Catalog chart
      const { data, error } = await (supabase as any)
        .from("chart_cve_catalog_severity")
        .select("*")
        .order("sort_order", { ascending: true });

      if (error) {
        if (
          error.code === "42P01" ||
          /relation .* does not exist/i.test(error.message ?? "")
        ) {
          return [];
        }
        throw error;
      }

      return (data ?? []).map((r: any) => ({
        name: r.segment_name,
        value: Number(r.segment_value) || 0,
        color: r.segment_color,
      }));
    },
    staleTime: 120_000,
  });
}
