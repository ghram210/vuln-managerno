import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import type { DonutSegment } from "@/components/DonutChart";

export function useCveCatalogChart() {
  return useQuery<DonutSegment[]>({
    queryKey: ["chart_cve_catalog_severity_discovery"],
    queryFn: async () => {
      // Filtered by auth.uid() in the database view (migration v5)
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
    staleTime: 60_000,
  });
}
