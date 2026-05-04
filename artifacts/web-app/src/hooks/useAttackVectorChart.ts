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
    queryKey: ["attack_vector_all_cves"],
    queryFn: async () => {
      // Fetch all CVE vectors from the full cve_catalog (not just finding_cves)
      // This gives a true distribution across Network/Adjacent/Local/Physical
      const { data, error } = await (supabase as any)
        .from("cve_catalog")
        .select("cvss_v3_vector");

      if (error) {
        if (
          error.code === "42P01" ||
          /relation .* does not exist/i.test(error.message ?? "")
        ) {
          return [];
        }
        throw error;
      }

      const counts: Record<string, number> = {};
      for (const row of data ?? []) {
        const bucket = classifyVector(row.cvss_v3_vector);
        counts[bucket] = (counts[bucket] ?? 0) + 1;
      }

      return Object.entries(counts)
        .filter(([, v]) => v > 0)
        .map(([name, value]) => ({
          name,
          value,
          color: AV_COLOR[name] ?? AV_COLOR.Unknown,
          _order: AV_ORDER[name] ?? 99,
        }))
        .sort((a, b) => (a as any)._order - (b as any)._order)
        .map(({ name, value, color }) => ({ name, value, color }));
    },
    staleTime: 120_000,
  });
}
