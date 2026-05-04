-- chart_cve_catalog_severity
-- Shows the CVSS v3 severity distribution of all CVEs imported into
-- the cve_catalog table from NVD / Exploit-DB local indexes.
-- Replaces the redundant chart_vulns_by_exprt donut on the main dashboard.

BEGIN;

DROP VIEW IF EXISTS public.chart_cve_catalog_severity;

CREATE OR REPLACE VIEW public.chart_cve_catalog_severity AS
SELECT
  COALESCE(cvss_v3_severity, 'UNKNOWN')   AS segment_name,
  COUNT(*)::int                            AS segment_value,
  CASE COALESCE(cvss_v3_severity, 'UNKNOWN')
    WHEN 'CRITICAL' THEN 'hsl(0 85% 52%)'
    WHEN 'HIGH'     THEN 'hsl(22 90% 54%)'
    WHEN 'MEDIUM'   THEN 'hsl(40 92% 52%)'
    WHEN 'LOW'      THEN 'hsl(160 65% 46%)'
    WHEN 'NONE'     THEN 'hsl(220 18% 62%)'
    ELSE                 'hsl(250 18% 58%)'
  END                                      AS segment_color,
  CASE COALESCE(cvss_v3_severity, 'UNKNOWN')
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH'     THEN 2
    WHEN 'MEDIUM'   THEN 3
    WHEN 'LOW'      THEN 4
    WHEN 'NONE'     THEN 5
    ELSE                 6
  END                                      AS sort_order
FROM public.cve_catalog
GROUP BY cvss_v3_severity
HAVING COUNT(*) > 0;

GRANT SELECT ON public.chart_cve_catalog_severity TO anon, authenticated;

COMMIT;
