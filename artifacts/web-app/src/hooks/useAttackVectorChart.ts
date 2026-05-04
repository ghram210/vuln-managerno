import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import type { DonutSegment } from "@/components/DonutChart";

const AV_COLOR: Record<string, string> = {
  Network:  "hsl(142 85% 42%)",
  Adjacent: "hsl(160 78% 48%)",
  Local:    "hsl(120 65% 52%)",
  Physical: "hsl(90 55% 58%)",
  Unknown:  "hsl(215 20% 65%)",
};
const AV_ORDER: Record<string, number> = {
  Network: 1, Adjacent: 2, Local: 3, Physical: 4, Unknown: 5,
};

function classifyVector(vec: string | null): string {
  if (!vec) return "Unknown";
  const v = vec.toUpperCase();
  if (v.includes("AV:N")) return "Network";
  if (v.includes("AV:A")) return "Adjacent";
  if (v.includes("AV:L")) return "Local";
  if (v.includes("AV:P")) return "Physical";
  return "Unknown";
}

export function useAttackVectorChart() {
  return useQuery<DonutSegment[]>({
    queryKey: ["attack_vector_user_scans"],
    queryFn: async () => {
      // Fetch from the new user-specific view that includes zero-value buckets
      const { data, error } = await (supabase as any)
        .from("chart_attack_vector")
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
